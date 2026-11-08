package forwardproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// UDPConfig is deliberately opt-in. These limits apply on the server, including
// to clients other than naive. JSON durations use Caddy duration syntax.
type UDPConfig struct {
	IdleTimeout        caddy.Duration `json:"idle_timeout,omitempty"`
	MaxSessions        int            `json:"max_sessions,omitempty"`
	MaxSessionsPerUser int            `json:"max_sessions_per_user,omitempty"`
	PacketsPerSecond   int            `json:"packets_per_second,omitempty"`
}
type udpUser struct {
	active  int
	packets *rate.Limiter
}
type udpState struct {
	sync.Mutex
	users   map[string]*udpUser
	active  int
	creates *rate.Limiter
}

var processUDPSessions atomic.Int64

func (h *Handler) provisionUDP() error {
	if h.UDP == nil {
		return nil
	}
	if len(h.AuthCredentials) == 0 {
		return errors.New("udp requires forward_proxy basic_auth")
	}
	if h.Upstream != "" {
		return errors.New("udp does not support upstream proxy chaining")
	}
	c := h.UDP
	if c.IdleTimeout == 0 {
		c.IdleTimeout = caddy.Duration(120 * time.Second)
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 1024
	}
	if c.MaxSessionsPerUser == 0 {
		c.MaxSessionsPerUser = min(128, c.MaxSessions)
	}
	if c.PacketsPerSecond == 0 {
		c.PacketsPerSecond = 2000
	}
	if time.Duration(c.IdleTimeout) < 2*time.Minute || c.MaxSessions < 1 || c.MaxSessions > 4096 || c.MaxSessionsPerUser < 1 || c.MaxSessionsPerUser > c.MaxSessions || c.PacketsPerSecond < 1 || c.PacketsPerSecond > 1000000 {
		return errors.New("invalid udp limits (idle >= 2m, sessions <= 4096, user sessions <= sessions, packet rate <= 1000000)")
	}
	h.udpState = &udpState{users: make(map[string]*udpUser), creates: rate.NewLimiter(100, 200)}
	return nil
}
func (h *Handler) admitUDP(user string) (*udpUser, func(), bool) {
	s := h.udpState
	s.Lock()
	defer s.Unlock()
	if !s.creates.Allow() || s.active >= h.UDP.MaxSessions {
		return nil, nil, false
	}
	u := s.users[user]
	if u != nil && u.active >= h.UDP.MaxSessionsPerUser {
		return nil, nil, false
	}
	if processUDPSessions.Add(1) > 4096 {
		processUDPSessions.Add(-1)
		return nil, nil, false
	}
	if u == nil {
		u = &udpUser{packets: rate.NewLimiter(rate.Limit(h.UDP.PacketsPerSecond), h.UDP.PacketsPerSecond)}
		s.users[user] = u
	}
	u.active++
	s.active++
	return u, func() {
		s.Lock()
		defer s.Unlock()
		u.active--
		s.active--
		processUDPSessions.Add(-1)
	}, true
}
func extendedConnectProtocol(r *http.Request) string {
	if r.ProtoMajor == 3 && r.Proto != "HTTP/3.0" && r.Proto != "HTTP/3" {
		return r.Proto
	}
	return r.Header.Get(":protocol")
}
func connectUDPTarget(r *http.Request) (string, uint16, error) {
	if r.URL == nil || r.URL.Scheme != "https" || r.Host == "" {
		return "", 0, errors.New("invalid CONNECT-UDP origin")
	}
	const prefix = "/.well-known/masque/udp/"
	path := r.URL.EscapedPath()
	if !strings.HasPrefix(path, prefix) || r.URL.RawQuery != "" {
		return "", 0, errors.New("unsupported CONNECT-UDP URI template")
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) != 3 || parts[2] != "" {
		return "", 0, errors.New("invalid CONNECT-UDP path")
	}
	host, err := url.PathUnescape(parts[0])
	if err != nil || host == "" || len(host) > 253 || strings.ContainsAny(host, "/%[]\\\x00 \r\n\t?#@") {
		return "", 0, errors.New("invalid target host")
	}
	if strings.Contains(host, ":") {
		if _, err = netip.ParseAddr(host); err != nil {
			return "", 0, errors.New("invalid IPv6 host")
		}
	}
	port, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil || port == 0 {
		return "", 0, errors.New("invalid target port")
	}
	return strings.ToLower(host), uint16(port), nil
}
func (h *Handler) dialUDP(ctx context.Context, host string, port uint16) (*net.UDPConn, error) {
	if !h.portIsAllowed(strconv.Itoa(int(port))) {
		return nil, caddyhttp.Error(403, errors.New("UDP port denied"))
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(h.DialTimeout))
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, caddyhttp.Error(502, err)
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.IsUnspecified() || ip.IsMulticast() || ip == netip.MustParseAddr("255.255.255.255") || !h.hostIsAllowed(host, net.IP(ip.AsSlice())) {
			continue
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
		if err != nil {
			return nil, caddyhttp.Error(502, err)
		}
		udp := conn.(*net.UDPConn)
		if err = configureUDPNoFragment(udp, ip.Is6()); err != nil {
			udp.Close()
			return nil, caddyhttp.Error(502, err)
		}
		return udp, nil
	}
	return nil, caddyhttp.Error(403, errors.New("no allowed UDP target IP"))
}
func unwrapHTTP3(w http.ResponseWriter) (http3.HTTPStreamer, http3.Settingser) {
	for i := 0; i < 16; i++ {
		stream, sok := w.(http3.HTTPStreamer)
		settings, cok := w.(http3.Settingser)
		if sok && cok {
			return stream, settings
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		w = u.Unwrap()
	}
	return nil, nil
}
func (h *Handler) serveConnectUDP(w http.ResponseWriter, r *http.Request) error {
	if h.UDP == nil || h.udpState == nil {
		return caddyhttp.Error(501, errors.New("UDP proxy disabled"))
	}
	if r.ProtoMajor != 3 {
		return caddyhttp.Error(501, errors.New("UDP requires HTTP/3 DATAGRAM"))
	}
	// Authentication has already run in ServeHTTP. No early data is forwarded.
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		return caddyhttp.Error(425, errors.New("UDP early data is not accepted"))
	}
	if r.Header.Get("Capsule-Protocol") != "?1" {
		return caddyhttp.Error(400, errors.New("Capsule-Protocol required"))
	}
	host, port, err := connectUDPTarget(r)
	if err != nil {
		return caddyhttp.Error(400, err)
	}
	transport, settings := unwrapHTTP3(w)
	if transport == nil {
		return caddyhttp.Error(501, errors.New("Caddy HTTP/3 DATAGRAM patch required"))
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-settings.ReceivedSettings():
	case <-r.Context().Done():
		return r.Context().Err()
	case <-timer.C:
		return caddyhttp.Error(408, errors.New("SETTINGS timeout"))
	}
	if !settings.Settings().EnableDatagrams {
		return caddyhttp.Error(501, errors.New("peer did not enable H3 DATAGRAM"))
	}
	// Identity is a validated, configured Basic credential, never logged.
	user, release, ok := h.admitUDP(strings.SplitN(r.Header.Get("Proxy-Authorization"), " ", 2)[1])
	if !ok {
		return caddyhttp.Error(429, errors.New("UDP session limit"))
	}
	defer release()
	udp, err := h.dialUDP(r.Context(), host, port)
	if err != nil {
		return err
	}
	defer udp.Close()
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(200)
	if err = http.NewResponseController(w).Flush(); err != nil {
		return err
	}
	// DATAGRAM activity does not read the HTTP request body. Override Caddy's
	// body-idle timers; relayUDP enforces its own bidirectional idle limit.
	if reader, writer := caddyhttp.IdleTimeoutsFromContext(r.Context()); reader != nil {
		reader.Override(24*time.Hour, 0)
		if writer != nil {
			writer.Override(24*time.Hour, 0, 0)
		}
	}
	stream := transport.HTTPStream()
	started := time.Now()
	stats := new(udpRelayStats)
	err = relayUDP(r.Context(), udp, stream, time.Duration(h.UDP.IdleTimeout), user.packets, stats)
	h.logger.Debug("UDP tunnel closed", zap.Duration("duration", time.Since(started)),
		zap.Uint64("sent_packets", stats.sent.Load()), zap.Uint64("received_packets", stats.received.Load()),
		zap.Uint64("dropped_packets", stats.dropped.Load()), zap.Error(err))
	return err
}

// relayUDP keeps control, datagram and target reads independent. Closing any
// direction cancels all tasks and waits for them, including a blocked control
// read, before the handler releases its quotas and socket.
type udpRelayStats struct{ sent, received, dropped atomic.Uint64 }

func relayUDP(parent context.Context, udp *net.UDPConn, stream *http3.Stream, idle time.Duration, limiter *rate.Limiter, stats *udpRelayStats) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	touch := func() { last.Store(time.Now().UnixNano()) }
	errorsCh := make(chan error, 3)
	go func() { errorsCh <- readUDPCapsules(stream, udp, limiter, touch) }()
	go func() {
		for {
			packet, err := stream.ReceiveDatagram(ctx)
			if err != nil {
				errorsCh <- err
				return
			}
			payload, known, err := decodeUDPDatagram(packet)
			if err != nil {
				errorsCh <- err
				return
			}
			if !known || !limiter.Allow() {
				stats.dropped.Add(1)
				continue
			}
			_, err = udp.Write(payload)
			if err != nil {
				if isUDPTooLarge(err) {
					stats.dropped.Add(1)
					continue
				}
				errorsCh <- err
				return
			}
			stats.sent.Add(1)
			touch()
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := udp.Read(buf[1:])
			if err != nil {
				errorsCh <- err
				return
			}
			if n > 65527 || !limiter.Allow() {
				stats.dropped.Add(1)
				continue
			}
			buf[0] = 0
			err = stream.SendDatagram(buf[:n+1])
			if err != nil {
				var large *quic.DatagramTooLargeError
				if errors.As(err, &large) {
					stats.dropped.Add(1)
					continue
				}
				errorsCh <- err
				return
			}
			stats.received.Add(1)
			touch()
		}
	}()
	ticker := time.NewTicker(min(idle/4, time.Second*5))
	defer ticker.Stop()
	var result error
	reports := 0
	active := true
	for active {
		select {
		case result = <-errorsCh:
			reports++
			active = false
		case <-parent.Done():
			result = parent.Err()
			active = false
		case <-ticker.C:
			if time.Since(time.Unix(0, last.Load())) >= idle {
				result = context.DeadlineExceeded
				active = false
			}
		}
	}
	cancel()
	udp.Close()
	stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	for ; reports < 3; reports++ {
		<-errorsCh
	}
	if errors.Is(result, io.EOF) || errors.Is(result, net.ErrClosed) || errors.Is(result, context.Canceled) {
		return nil
	}
	return result
}

func readVarint(r io.Reader) (uint64, error) {
	var b [8]byte
	n, err := io.ReadFull(r, b[:1])
	if err != nil {
		return 0, err
	}
	_ = n
	length := 1 << (b[0] >> 6)
	v := uint64(b[0] & 63)
	if _, err = io.ReadFull(r, b[1:length]); err != nil {
		return 0, io.ErrUnexpectedEOF
	}
	for _, c := range b[1:length] {
		v = v<<8 | uint64(c)
	}
	return v, nil
}
func decodeUDPDatagram(packet []byte) ([]byte, bool, error) {
	if len(packet) == 0 {
		return nil, false, errors.New("missing Context ID")
	}
	n := 1 << (packet[0] >> 6)
	if len(packet) < n {
		return nil, false, errors.New("truncated Context ID")
	}
	contextID := uint64(packet[0] & 63)
	for _, b := range packet[1:n] {
		contextID = contextID<<8 | uint64(b)
	}
	if contextID != 0 {
		return nil, false, nil
	}
	if len(packet)-n > 65527 {
		return nil, false, errors.New("UDP payload exceeds 65527")
	}
	return packet[n:], true, nil
}
func readUDPCapsules(r io.Reader, udp *net.UDPConn, limiter *rate.Limiter, touch func()) error {
	// Bound memory for control frames. There is no send-side Capsule fallback;
	// accepting peer DATAGRAM capsules preserves RFC 9297 interoperability.
	buf := make([]byte, 65536)
	for {
		typ, err := readVarint(r)
		if err != nil {
			return err
		}
		length, err := readVarint(r)
		if err != nil {
			return fmt.Errorf("capsule length: %w", io.ErrUnexpectedEOF)
		}
		if length > uint64(len(buf)) {
			return errors.New("capsule exceeds control budget")
		}
		if _, err = io.ReadFull(r, buf[:length]); err != nil {
			return io.ErrUnexpectedEOF
		}
		if typ != 0 {
			continue
		}
		payload, known, err := decodeUDPDatagram(buf[:length])
		if err != nil {
			return err
		}
		if !known || !limiter.Allow() {
			continue
		}
		if _, err = udp.Write(payload); err != nil {
			if isUDPTooLarge(err) {
				continue
			}
			return err
		}
		touch()
	}
}

func isUDPTooLarge(err error) bool { return errors.Is(err, syscall.EMSGSIZE) }

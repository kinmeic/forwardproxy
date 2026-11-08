package forwardproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/sagernet/quic-go/http3"
	"golang.org/x/time/rate"
)

func TestUDPTargetValidation(t *testing.T) {
	for _, tc := range []struct {
		path, host string
		port       uint16
		valid      bool
	}{
		{"/.well-known/masque/udp/example.com/53/", "example.com", 53, true},
		{"/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/", "2001:db8::1", 443, true},
		{"/.well-known/masque/udp/127.0.0.1/0/", "", 0, false},
		{"/.well-known/masque/udp/a%2Fb/53/", "", 0, false},
		{"/.well-known/masque/udp/fe80%3A%3A1%25en0/53/", "", 0, false},
		{"/.well-known/masque/udp/example.com/65536/", "", 0, false},
		{"/.well-known/masque/udp/example.com/53", "", 0, false},
	} {
		u, err := url.Parse("https://proxy.test" + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		host, port, err := connectUDPTarget(&http.Request{Host: "proxy.test", URL: u})
		if (err == nil) != tc.valid || host != tc.host || port != tc.port {
			t.Fatalf("%s: %s:%d %v", tc.path, host, port, err)
		}
	}
}
func TestUDPDatagramBoundaries(t *testing.T) {
	for _, packet := range [][]byte{{0}, {0, 'x'}, {0x40, 0, 'x'}, {1, 'x'}} {
		payload, known, err := decodeUDPDatagram(packet)
		if err != nil {
			t.Fatal(err)
		}
		if packet[0] == 1 {
			if known {
				t.Fatal("unknown context accepted")
			}
		} else if !known || len(payload) > 1 {
			t.Fatal("valid context rejected")
		}
	}
	for _, packet := range [][]byte{nil, {0x40}, append([]byte{0}, make([]byte, 65528)...)} {
		if _, _, err := decodeUDPDatagram(packet); err == nil {
			t.Fatal("bad datagram accepted")
		}
	}
}
func TestUDPAdmissionAndConfiguration(t *testing.T) {
	h := &Handler{UDP: &UDPConfig{MaxSessions: 2, MaxSessionsPerUser: 1}, AuthCredentials: [][]byte{EncodeAuthCredentials("u", "p")}}
	if err := h.provisionUDP(); err != nil {
		t.Fatal(err)
	}
	_, release, ok := h.admitUDP("u")
	if !ok {
		t.Fatal("first admission")
	}
	if _, _, ok = h.admitUDP("u"); ok {
		t.Fatal("per-user quota bypassed")
	}
	_, release2, ok := h.admitUDP("v")
	if !ok {
		t.Fatal("second user")
	}
	if _, _, ok = h.admitUDP("w"); ok {
		t.Fatal("handler quota bypassed")
	}
	release()
	release2()
	if h.udpState.active != 0 {
		t.Fatal("quota leaked")
	}
	for _, h := range []*Handler{
		{UDP: &UDPConfig{}},
		{UDP: &UDPConfig{}, Upstream: "https://x", AuthCredentials: [][]byte{EncodeAuthCredentials("u", "p")}},
		{UDP: &UDPConfig{IdleTimeout: caddy.Duration(time.Second)}, AuthCredentials: [][]byte{EncodeAuthCredentials("u", "p")}},
		{UDP: &UDPConfig{}, AuthCredentials: [][]byte{[]byte("invalid base64")}},
		{UDP: &UDPConfig{}, AuthCredentials: [][]byte{[]byte(base64.StdEncoding.EncodeToString([]byte("no-colon")))}},
		{UDP: &UDPConfig{}, AuthCredentials: [][]byte{EncodeAuthCredentials("", "p")}},
	} {
		if h.provisionUDP() == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
}

func TestUDPProbeResistance(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	h := &Handler{UDP: &UDPConfig{}, ProbeResistance: &ProbeResistance{}, AuthCredentials: [][]byte{EncodeAuthCredentials("u", "p")}}
	if err := h.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	for _, auth := range []string{"", "Basic dTpiYWQ=", "Basic %invalid", "Bearer token"} {
		for _, path := range []string{"/.well-known/masque/udp/example.com/53/", "/invalid"} {
			r := httptest.NewRequest("CONNECT", "https://proxy.test"+path, nil)
			r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
			r.ProtoMajor, r.Proto = 3, "connect-udp"
			r.Header.Set("Proxy-Authorization", auth)
			// Deliberately omit Capsule-Protocol and the H3 writer interface:
			// authentication hiding must run before capability/URI validation.
			w := httptest.NewRecorder()
			err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusNotFound)
				_, err := w.Write([]byte("ordinary site"))
				return err
			}))
			if err != nil || w.Code != http.StatusNotFound || w.Body.String() != "ordinary site" || w.Header().Get("Proxy-Authenticate") != "" || w.Header().Get("Capsule-Protocol") != "" {
				t.Fatalf("unauthenticated probe exposed proxy: status=%d headers=%v err=%v", w.Code, w.Header(), err)
			}
		}
	}
	if h.udpState.active != 0 || len(h.udpState.users) != 0 {
		t.Fatal("unauthenticated probe acquired UDP resources")
	}
}
func TestUDPVarintTruncation(t *testing.T) {
	if _, err := readVarint(bytes.NewReader([]byte{0x40})); err != io.ErrUnexpectedEOF {
		t.Fatal(err)
	}
}
func TestUDPDialACLAndNoFragment(t *testing.T) {
	h := &Handler{DialTimeout: caddy.Duration(time.Second)}
	// Deny is the default when no rules match, even for numeric target IPs.
	if c, err := h.dialUDP(context.Background(), "127.0.0.1", 53); err == nil {
		c.Close()
		t.Fatal("ACL bypass")
	}
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = configureUDPNoFragment(c, false); err != nil {
		t.Fatal(err)
	}
}

func TestUDPRedirectComparison(t *testing.T) {
	response := func(location string) *http.Response {
		w := httptest.NewRecorder()
		w.Header().Set("Location", location)
		w.WriteHeader(307)
		return w.Result()
	}
	if err := redirectResponsesAreEqual(response("https://a.test/path"), response("https://b.test/path"), "a.test", "b.test"); err != nil {
		t.Fatal(err)
	}
	if err := redirectResponsesAreEqual(response("https://evil.test/path"), response("https://b.test/path"), "a.test", "b.test"); err == nil {
		t.Fatal("incorrect redirect accepted")
	}
	if err := redirectResponsesAreEqual(response("https://a.test/other"), response("https://b.test/path"), "a.test", "b.test"); err == nil {
		t.Fatal("path difference hidden")
	}
}

// Exercise the legacy redirect fixtures on ordinary loopback as well, so this
// regression can run on macOS without installing extra 127.x address aliases.
func TestUDPRedirectIntegration(t *testing.T) {
	for _, creds := range credentialsWrong {
		for _, resource := range testResources {
			for _, self := range []bool{false, true} {
				targetA, targetB := caddyTestTarget.addr, caddyTestTarget.addr
				if self {
					targetA = caddyForwardProxyProbeResist.addr
					targetB = caddyDummyProbeResist.addr
				}
				addrA := net.JoinHostPort("127.0.0.1", caddyForwardProxyProbeResist.httpRedirPort)
				addrB := net.JoinHostPort("127.0.0.1", caddyDummyProbeResist.httpRedirPort)
				for _, connect := range []bool{false, true} {
					var a, b *http.Response
					var err error
					if connect {
						a, err = connectAndGetViaProxy(targetA, resource, addrA, "HTTP/1.1", creds, "HTTP/1.1", false)
						if err == nil {
							b, err = connectAndGetViaProxy(targetB, resource, addrB, "HTTP/1.1", creds, "HTTP/1.1", false)
						}
					} else {
						a, err = getViaProxy(targetA, resource, addrA, "HTTP/1.1", creds, false)
						if err == nil {
							b, err = getViaProxy(targetB, resource, addrB, "HTTP/1.1", creds, false)
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					if err = redirectResponsesAreEqual(a, b, caddyForwardProxyProbeResist.addr, caddyDummyProbeResist.addr); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
}

// A peer may delay its control stream even after authenticating. Such a
// request must consume admission quota until negotiation ends or is canceled.
type pendingUDPWriter struct {
	*httptest.ResponseRecorder
	ready chan struct{}
}

func (w *pendingUDPWriter) HTTPStream() *http3.Stream         { panic("stream takeover before negotiation") }
func (w *pendingUDPWriter) ReceivedSettings() <-chan struct{} { return w.ready }
func (w *pendingUDPWriter) Settings() *http3.Settings         { return &http3.Settings{EnableDatagrams: true} }

func TestUDPPendingSettingsAdmission(t *testing.T) {
	h := &Handler{UDP: &UDPConfig{MaxSessions: 1}, AuthCredentials: [][]byte{EncodeAuthCredentials("u", "p")}}
	if err := h.provisionUDP(); err != nil {
		t.Fatal(err)
	}
	request := func(ctx context.Context) *http.Request {
		r, _ := http.NewRequestWithContext(ctx, "CONNECT", "https://proxy.test/.well-known/masque/udp/example.com/53/", nil)
		r.ProtoMajor = 3
		r.Proto = "connect-udp"
		r.Header.Set("Capsule-Protocol", "?1")
		r.Header.Set("Proxy-Authorization", "Basic dTpw")
		return r
	}
	writer := func() *pendingUDPWriter { return &pendingUDPWriter{httptest.NewRecorder(), make(chan struct{})} }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.serveConnectUDP(writer(), request(ctx)) }()
	deadline := time.Now().Add(time.Second)
	for {
		h.udpState.Lock()
		active := h.udpState.active
		h.udpState.Unlock()
		if active == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SETTINGS waiter did not acquire quota")
		}
		time.Sleep(time.Millisecond)
	}
	second, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	err := h.serveConnectUDP(writer(), request(second))
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != 429 {
		t.Fatalf("expected quota rejection, got %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SETTINGS cancellation leaked request")
	}
	h.udpState.Lock()
	active := h.udpState.active
	h.udpState.Unlock()
	if active != 0 {
		t.Fatal("SETTINGS cancellation leaked quota")
	}
}

func TestUDPUnknownContextConsumesRate(t *testing.T) {
	limiter := rate.NewLimiter(0, 1)
	stats := new(udpRelayStats)
	touched := false
	touch := func() { touched = true }
	// Nil UDP is intentional: neither the unknown frame nor the next, now
	// rate-limited valid frame may reach the socket.
	if err := forwardUDPDatagram(nil, []byte{1}, limiter, stats, touch); err != nil {
		t.Fatal(err)
	}
	if err := forwardUDPDatagram(nil, []byte{0, 'x'}, limiter, stats, touch); err != nil {
		t.Fatal(err)
	}
	if touched || stats.sent.Load() != 0 || stats.dropped.Load() != 2 {
		t.Fatal("unknown context bypassed packet budget")
	}
}

func TestUDPCapsuleFloodAndTruncation(t *testing.T) {
	stats := new(udpRelayStats)
	for _, packet := range [][]byte{{0x40}, {0}, {0, 0}, {0, 1}} {
		if err := readUDPCapsules(bytes.NewReader(packet), nil, rate.NewLimiter(0, 1), stats, func() {}); err == nil {
			t.Fatalf("accepted truncated/malformed capsule %x", packet)
		}
	}
	// Each unknown capsule is type=1, length=0. Its lack of payload must not
	// allow unlimited control processing while bypassing business packet limits.
	packet := bytes.Repeat([]byte{1, 0}, 10000)
	err := readUDPCapsules(bytes.NewReader(packet), nil, rate.NewLimiter(0, 1), stats, func() {})
	if err == nil || !strings.Contains(err.Error(), "rate exceeded") {
		t.Fatalf("unbounded control processing: %v", err)
	}
}

func TestUDPPrivateAddressPolicy(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	h := &Handler{}
	if err := h.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"fd00::1", "fc00::1", "169.254.169.254"} {
		if h.hostIsAllowed(ip, net.ParseIP(ip)) {
			t.Fatalf("default ACL allows private/link-local %s", ip)
		}
	}
	// Explicit administrator rules retain precedence over the default deny list.
	allowed := &Handler{ACL: []ACLRule{{Allow: true, Subjects: []string{"fd00::/8"}}}}
	if err := allowed.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if !allowed.hostIsAllowed("fd00::1", net.ParseIP("fd00::1")) {
		t.Fatal("explicit private network allow was ignored")
	}
}

func TestUDPActivityDoesNotRegress(t *testing.T) {
	a := newUDPActivity()
	a.record(2 * time.Second)
	a.record(time.Second)
	if a.last.Load() != int64(2*time.Second) {
		t.Fatal("stale relay activity overwrote a newer timestamp")
	}
	// Shift the monotonic start rather than change the system clock or sleep.
	a.start = time.Now().Add(-time.Minute)
	a.last.Store(0)
	if a.inactiveFor() < time.Minute {
		t.Fatal("idle elapsed duration lost")
	}
	a.touch()
	if a.inactiveFor() > time.Second {
		t.Fatal("recent activity did not refresh monotonic idle timer")
	}
}

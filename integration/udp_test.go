package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	fp "github.com/caddyserver/forwardproxy"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

// Real QUIC DATAGRAM echo, including a wrapped ResponseWriter, empty payload,
// authentication, ACL rejection, unsupported capability, concurrent flows and
// request reset cleanup. It does not send business data in HTTP DATA frames.
func TestHTTP3UDP(t *testing.T) {
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			if bytes.Equal(buf[:n], []byte("large-reply")) {
				echo.WriteTo(make([]byte, 4000), addr)
			} else {
				echo.WriteTo(buf[:n], addr)
			}
		}
	}()
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	certs := certServer.TLS.Certificates
	certServer.Close()
	h := &fp.Handler{UDP: &fp.UDPConfig{MaxSessionsPerUser: 2}, AuthCredentials: [][]byte{fp.EncodeAuthCredentials("u", "p")}, ACL: []fp.ACLRule{{Allow: true, Subjects: []string{"127.0.0.1"}}}}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err = h.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: certs}, EnableDatagrams: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		if err := h.ServeHTTP(&caddyhttp.ResponseWriterWrapper{ResponseWriter: w}, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { w.WriteHeader(404); return nil })); err != nil {
			status := 500
			if e, ok := err.(caddyhttp.HandlerError); ok {
				status = e.StatusCode
			}
			w.WriteHeader(status)
		}
	})}
	defer server.Close()
	go server.Serve(listener)
	deadline, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	qconn, err := quic.DialAddr(deadline, listener.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer qconn.CloseWithError(0, "")
	transport := &http3.Transport{EnableDatagrams: true}
	defer transport.Close()
	client := transport.NewClientConn(qconn)
	select {
	case <-client.ReceivedSettings():
	case <-deadline.Done():
		t.Fatal(deadline.Err())
	}
	if !client.Settings().EnableDatagrams || !client.Settings().EnableExtendedConnect {
		t.Fatal("capabilities missing")
	}
	_, port, _ := net.SplitHostPort(echo.LocalAddr().String())
	open := func(host, p, auth string) (*http3.RequestStream, int) {
		t.Helper()
		stream, err := client.OpenRequestStream(deadline)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("CONNECT", fmt.Sprintf("https://%s/.well-known/masque/udp/%s/%s/", listener.LocalAddr(), host, p), nil)
		req.Proto = "connect-udp"
		req.Header.Set("Capsule-Protocol", "?1")
		req.Header.Set("Proxy-Authorization", auth)
		if err = stream.SendRequestHeader(req); err != nil {
			t.Fatal(err)
		}
		rsp, err := stream.ReadResponse()
		if err != nil {
			t.Fatal(err)
		}
		return stream, rsp.StatusCode
	}
	bad, status := open("127.0.0.1", port, "Basic dTpiYWQ=")
	if status != 407 {
		t.Fatalf("bad auth: %d", status)
	}
	bad.Close()
	denied, status := open("127.0.0.2", port, "Basic dTpw")
	if status != 403 {
		t.Fatalf("ACL: %d", status)
	}
	denied.Close()
	first, status := open("127.0.0.1", port, "Basic dTpw")
	if status != 200 {
		t.Fatalf("connect: %d", status)
	}
	second, status := open("127.0.0.1", port, "basic dTpw")
	if status != 200 {
		t.Fatalf("second: %d", status)
	}
	excess, status := open("127.0.0.1", port, "BASIC dTpw")
	if status != 429 {
		t.Fatalf("quota: %d", status)
	}
	excess.Close()
	// An oversized reply must be dropped, leaving the tunnel usable for the
	// following ordinary reply. This exercises the server's MTU error path.
	if err = first.SendDatagram(append([]byte{0}, []byte("large-reply")...)); err != nil {
		t.Fatal(err)
	}
	for _, stream := range []*http3.RequestStream{first, second} {
		for _, payload := range [][]byte{nil, []byte("hello"), bytes.Repeat([]byte{'x'}, 1000)} {
			packet := append([]byte{0}, payload...)
			if err = stream.SendDatagram(packet); err != nil {
				t.Fatal(err)
			}
			got, err := stream.ReceiveDatagram(deadline)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, packet) {
				t.Fatalf("datagram mismatch %d/%d", len(got), len(packet))
			}
		}
	}
	first.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	first.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	second.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	second.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	// Verify admission eventually recovers after both request streams reset.
	recovered := false
	for i := 0; i < 50; i++ {
		stream, status := open("127.0.0.1", port, "Basic dTpw")
		if status == 200 {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			recovered = true
			break
		}
		stream.Close()
		time.Sleep(10 * time.Millisecond)
	}
	if !recovered {
		t.Fatal("session quota not released after stream reset")
	}
}

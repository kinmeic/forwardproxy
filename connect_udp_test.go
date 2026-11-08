package forwardproxy

import (
	"bytes"
	"context"
	"github.com/caddyserver/caddy/v2"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
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
	for _, h := range []*Handler{{UDP: &UDPConfig{}}, {UDP: &UDPConfig{}, Upstream: "https://x", AuthCredentials: [][]byte{{1}}}, {UDP: &UDPConfig{IdleTimeout: caddy.Duration(time.Second)}, AuthCredentials: [][]byte{{1}}}} {
		if h.provisionUDP() == nil {
			t.Fatal("unsafe configuration accepted")
		}
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

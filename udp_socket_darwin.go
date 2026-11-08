//go:build darwin

package forwardproxy

import (
	"golang.org/x/sys/unix"
	"net"
)

func configureUDPNoFragment(conn *net.UDPConn, ipv6 bool) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		if ipv6 {
			socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
		} else {
			socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		}
	})
	if err != nil {
		return err
	}
	return socketErr
}

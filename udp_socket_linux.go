//go:build linux

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
			socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
		} else {
			socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
		}
	})
	if err != nil {
		return err
	}
	return socketErr
}

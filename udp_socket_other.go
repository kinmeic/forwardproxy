//go:build !linux && !darwin

package forwardproxy

import (
	"errors"
	"net"
)

func configureUDPNoFragment(*net.UDPConn, bool) error {
	return errors.New("CONNECT-UDP requires Linux or macOS no-fragment socket support")
}

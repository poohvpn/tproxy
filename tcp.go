package tproxy

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func ListenTCP(network string, laddr *net.TCPAddr) (*net.TCPListener, error) {
	listener, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
		}
	}()

	f, err := listener.File()
	if err != nil {
		return nil, &net.OpError{
			Op:   "listen",
			Net:  network,
			Addr: laddr,
			Err:  fmt.Errorf("get file descriptor: %s", err),
		}
	}
	defer f.Close()

	fd := int(f.Fd())

	if laddr == nil || laddr.IP == nil || laddr.IP.To4() != nil {
		err = syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
		if err != nil {
			return nil, &net.OpError{
				Op:   "listen",
				Net:  network,
				Addr: laddr,
				Err:  fmt.Errorf("set socket option IP_TRANSPARENT: %s", err),
			}
		}
	}

	if laddr == nil || laddr.IP == nil || (laddr.IP.To16() != nil && laddr.IP.To4() == nil) {
		err = syscall.SetsockoptInt(fd, syscall.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		if err != nil {
			return nil, &net.OpError{
				Op:   "listen",
				Net:  network,
				Addr: laddr,
				Err:  fmt.Errorf("set socket option IPV6_TRANSPARENT: %s", err),
			}
		}
	}

	return listener, nil
}

func DialTCPConn(conn *net.TCPConn, bindOriginAddr bool) (*net.TCPConn, error) {
	remoteAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteSockaddr, err := tcpAddrToSockaddr(remoteAddr)
	if err != nil {
		return nil, &net.OpError{
			Op:  "dial",
			Err: fmt.Errorf("build destination socket address: %s", err),
		}
	}

	bindSockaddr, err := tcpAddrToSockaddr(conn.RemoteAddr().(*net.TCPAddr))
	if err != nil {
		return nil, &net.OpError{
			Op:  "dial",
			Err: fmt.Errorf("build local socket address: %s", err),
		}
	}

	family := ipToFamily(remoteAddr.IP)
	fd, err := syscall.Socket(family, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, &net.OpError{
			Op:  "dial",
			Err: fmt.Errorf("socket open: %s", err),
		}
	}
	defer func() {
		if err != nil {
			_ = syscall.Close(fd)
		}
	}()

	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		return nil, &net.OpError{
			Op:  "dial",
			Err: fmt.Errorf("set socket option SO_REUSEADDR: %s", err),
		}
	}

	if family == syscall.AF_INET {
		err = syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
		if err != nil {
			return nil, &net.OpError{
				Op:  "dial",
				Err: fmt.Errorf("set socket option IP_TRANSPARENT: %s", err),
			}
		}
	} else {
		err = syscall.SetsockoptInt(fd, syscall.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		if err != nil {
			return nil, &net.OpError{
				Op:  "dial",
				Err: fmt.Errorf("set socket option IP_TRANSPARENT: %s", err),
			}
		}
	}

	err = syscall.SetNonblock(fd, true)
	if err != nil {
		return nil, &net.OpError{
			Op:  "dial",
			Err: fmt.Errorf("set socket option SO_NONBLOCK: %s", err),
		}
	}

	if bindOriginAddr {
		err = syscall.Bind(fd, bindSockaddr)
		if err != nil {
			return nil, &net.OpError{
				Op:  "dial",
				Err: fmt.Errorf("socket bind: %s", err),
			}
		}
	}

	err = syscall.Connect(fd, remoteSockaddr)
	if err != nil && !strings.Contains(err.Error(), "operation now in progress") {
		return nil, &net.OpError{
			Op:  "dial",
			Err: fmt.Errorf("socket connect: %s", err),
		}
	}

	f := os.NewFile(uintptr(fd), connName(conn))
	defer f.Close()

	rconn, err := net.FileConn(f)
	if err != nil {
		return nil, &net.OpError{
			Op:  "dial",
			Err: fmt.Errorf("convert file descriptor to connection: %s", err),
		}
	}

	return rconn.(*net.TCPConn), nil
}

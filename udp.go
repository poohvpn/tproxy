package tproxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func ListenUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	listener, err := net.ListenUDP(network, laddr)
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
		err = syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1)
		if err != nil {
			return nil, &net.OpError{
				Op:   "listen",
				Net:  network,
				Addr: laddr,
				Err:  fmt.Errorf("set socket option IP_RECVORIGDSTADDR: %s", err),
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
		err = syscall.SetsockoptInt(fd, syscall.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
		if err != nil {
			return nil, &net.OpError{
				Op:   "listen",
				Net:  network,
				Addr: laddr,
				Err:  fmt.Errorf("set socket option IPV6_RECVORIGDSTADDR: %s", err),
			}
		}
	}

	return listener, nil
}

func ReadFromUDP(conn *net.UDPConn, b []byte) (n int, raddr *net.UDPAddr, dstAddr *net.UDPAddr, err error) {
	oob := make([]byte, 1024)
	n, oobn, _, raddr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return
	}

	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, nil, nil, fmt.Errorf("parsing socket control message: %s", err)
	}

	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP &&
			msg.Header.Type == syscall.IP_RECVORIGDSTADDR &&
			len(msg.Data) >= 8 && nativeEndian.Uint16(msg.Data[:2]) == syscall.AF_INET {
			dstAddr = &net.UDPAddr{
				Port: int(binary.BigEndian.Uint16(msg.Data[2:4])),
				IP:   msg.Data[4:8],
			}
			break
		} else if msg.Header.Level == syscall.SOL_IPV6 &&
			msg.Header.Type == unix.IPV6_RECVORIGDSTADDR &&
			len(msg.Data) >= 28 && nativeEndian.Uint16(msg.Data[:2]) == syscall.AF_INET6 {
			var ip [net.IPv6len]byte
			copy(ip[:], msg.Data[8:24])
			dstAddr = sockaddrToUDP(&syscall.SockaddrInet6{
				Port:   int(binary.BigEndian.Uint16(msg.Data[2:4])),
				Addr:   ip,
				ZoneId: binary.BigEndian.Uint32(msg.Data[24:28]),
			}).(*net.UDPAddr)
			break
		}
	}

	if dstAddr == nil {
		return 0, nil, nil, fmt.Errorf("unable to obtain original udp destination from %s", raddr.String())
	}

	return
}

func DialUDP(laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	remoteSockaddr, err := udpAddrToSockaddr(raddr)
	if err != nil {
		return nil, &net.OpError{
			Op:  "dial",
			Err: fmt.Errorf("build destination socket address: %s", err),
		}
	}

	bindSockaddr, err := udpAddrToSockaddr(laddr)
	if err != nil {
		return nil, &net.OpError{
			Op:  "dial",
			Err: fmt.Errorf("build local socket address: %s", err),
		}
	}

	family := ipToFamily(raddr.IP)
	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM, 0)
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

	err = syscall.Bind(fd, bindSockaddr)
	if err != nil {
		return nil, &net.OpError{
			Op:  "dial",
			Err: fmt.Errorf("socket bind: %s", err),
		}
	}

	err = syscall.Connect(fd, remoteSockaddr)
	if err != nil {
		return nil, &net.OpError{
			Op:  "dial",
			Err: fmt.Errorf("socket connect: %s", err),
		}
	}

	fdFile := os.NewFile(uintptr(fd), addrName(laddr, raddr))
	defer fdFile.Close()

	rconn, err := net.FileConn(fdFile)
	if err != nil {
		return nil, &net.OpError{
			Op:  "dial",
			Err: fmt.Errorf("open file conn: %s", err),
		}
	}

	return rconn.(*net.UDPConn), nil
}

package tproxy

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

//go:linkname ipToSockaddr net.ipToSockaddr
func ipToSockaddr(family int, ip net.IP, port int, zone string) (syscall.Sockaddr, error)

//go:linkname sockaddrToUDP net.sockaddrToUDP
func sockaddrToUDP(sa syscall.Sockaddr) net.Addr

func ipToFamily(ip net.IP) int {
	if len(ip) <= net.IPv4len || ip.To4() != nil {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

func addrToSockaddr(ip net.IP, port int, zone string) (syscall.Sockaddr, error) {
	return ipToSockaddr(ipToFamily(ip), ip, port, zone)
}

func tcpAddrToSockaddr(addr *net.TCPAddr) (syscall.Sockaddr, error) {
	return addrToSockaddr(addr.IP, addr.Port, addr.Zone)
}

func udpAddrToSockaddr(addr *net.UDPAddr) (syscall.Sockaddr, error) {
	return addrToSockaddr(addr.IP, addr.Port, addr.Zone)
}

func connName(conn net.Conn) string {
	return addrName(conn.LocalAddr(), conn.RemoteAddr())
}

func addrName(laddr, raddr net.Addr) string {
	return raddr.Network() + ":" + raddr.String() + "->" + laddr.String()
}

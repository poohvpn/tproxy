package main

import (
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/poohvpn/tproxy"
)

func main() {
	log.Println("Starting GoLang TProxy example")
	var err error

	log.Println("Binding TCP TProxy listener to :8080")
	tcpListener, err := tproxy.ListenTCP("tcp", &net.TCPAddr{Port: 8080})
	if err != nil {
		log.Fatalf("Encountered error while binding listener: %s", err)
		return
	}
	defer tcpListener.Close()
	go listenTCP(tcpListener)

	log.Println("Binding UDP TProxy listener to :8080")
	udpListener, err := tproxy.ListenUDP("udp", &net.UDPAddr{Port: 8080})
	if err != nil {
		log.Fatalf("Encountered error while binding UDP listener: %s", err)
		return
	}

	defer udpListener.Close()
	go listenUDP(udpListener)

	interruptListener := make(chan os.Signal)
	signal.Notify(interruptListener, os.Interrupt)
	<-interruptListener

	log.Println("TProxy listener closing")
	os.Exit(0)
}

func listenTCP(listener *net.TCPListener) {
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				log.Printf("Temporary error while accepting connection: %s", netErr)
			}

			log.Fatalf("Unrecoverable error while accepting connection: %s", err)
			return
		}

		go handleTCPConn(conn)
	}
}

func handleTCPConn(conn *net.TCPConn) {
	log.Printf("Accepting TCP connection from %s with destination of %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	defer conn.Close()

	remoteConn, err := tproxy.DialTCPConn(conn, false)
	if err != nil {
		log.Printf("Failed to connect to original destination [%s]: %s", conn.LocalAddr().String(), err)
		return
	}
	defer remoteConn.Close()

	var streamWait sync.WaitGroup
	streamWait.Add(2)

	streamConn := func(dst io.ReadWriteCloser, src io.ReadWriteCloser) {
		defer dst.Close()
		defer src.Close()
		io.Copy(dst, src)
		streamWait.Done()
	}

	go streamConn(remoteConn, conn)
	go streamConn(conn, remoteConn)

	streamWait.Wait()
}

func listenUDP(listener *net.UDPConn) {
	for {
		buff := make([]byte, 1024)
		n, srcAddr, dstAddr, err := tproxy.ReadFromUDP(listener, buff)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				log.Printf("Temporary error while reading data: %s", netErr)
			}

			log.Fatalf("Unrecoverable error while reading data: %s", err)
			return
		}

		if dstAddr.IP.IsMulticast() ||
			dstAddr.IP.IsInterfaceLocalMulticast() ||
			dstAddr.IP.IsLinkLocalMulticast() ||
			dstAddr.IP[len(dstAddr.IP)-1] == 0xff {
			continue
		}

		go handleUDPConn(buff[:n], srcAddr, dstAddr)
	}
}

func handleUDPConn(data []byte, srcAddr, dstAddr *net.UDPAddr) {
	log.Printf("Accepting UDP connection from %s with destination of %s", srcAddr, dstAddr)

	localConn, err := tproxy.DialUDP(dstAddr, srcAddr)
	if err != nil {
		log.Printf("Failed to connect to original UDP source [%s]: %s", srcAddr.String(), err)
		return
	}
	defer localConn.Close()

	remoteConn, err := tproxy.DialUDP(srcAddr, dstAddr)
	if err != nil {
		log.Printf("Failed to connect to original UDP destination [%s]: %s", dstAddr.String(), err)
		return
	}
	defer remoteConn.Close()

	bytesWritten, err := remoteConn.Write(data)
	if err != nil {
		log.Printf("Encountered error while writing to remote [%s]: %s", remoteConn.RemoteAddr(), err)
		return
	} else if bytesWritten < len(data) {
		log.Printf("Not all bytes [%d < %d] in buffer written to remote [%s]", bytesWritten, len(data), remoteConn.RemoteAddr())
		return
	}

	data = make([]byte, 1024)
	remoteConn.SetReadDeadline(time.Now().Add(30 * time.Second)) // Add deadline to ensure it doesn't block forever
	bytesRead, err := remoteConn.Read(data)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return
		}

		log.Printf("Encountered error while reading from remote [%s]: %s", remoteConn.RemoteAddr(), err)
		return
	}

	bytesWritten, err = localConn.Write(data)
	if err != nil {
		log.Printf("Encountered error while writing to local [%s]: %s", localConn.RemoteAddr(), err)
		return
	} else if bytesWritten < bytesRead {
		log.Printf("Not all bytes [%d < %d] in buffer written to locoal [%s]", bytesWritten, len(data), remoteConn.RemoteAddr())
		return
	}
}

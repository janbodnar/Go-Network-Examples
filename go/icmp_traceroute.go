// This program is a simple ICMP traceroute tool. It sends ICMP echo requests
// with increasing TTL values to a host to discover the routers along the path.
//
// This program must be run as root.
//
// It requires the golang.org/x/net/icmp and golang.org/x/net/ipv4 packages:
// go get golang.org/x/net/icmp
// go get golang.org/x/net/ipv4
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	protocolICMP = 1
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <host>\n", os.Args[0])
		os.Exit(1)
	}
	host := os.Args[1]

	// Resolve the host to an IP address.
	dst, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		fmt.Printf("could not resolve host: %v\n", err)
		os.Exit(1)
	}

	// Create a raw socket connection.
	c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("error listening for ICMP packets: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	p := ipv4.NewPacketConn(c)
	if err := p.SetControlMessage(ipv4.FlagTTL|ipv4.FlagSrc|ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		fmt.Printf("error setting control message: %v\n", err)
		os.Exit(1)
	}

	// Create the ICMP message.
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("hello"),
		},
	}

	rb := make([]byte, 1500)
	for i := 1; i <= 64; i++ { // Max 64 hops
		wm.Body.(*icmp.Echo).Seq = i
		wb, err := wm.Marshal(nil)
		if err != nil {
			fmt.Printf("error marshalling ICMP message: %v\n", err)
			os.Exit(1)
		}

		if err := p.SetTTL(i); err != nil {
			fmt.Printf("error setting TTL: %v\n", err)
			os.Exit(1)
		}

		// Send the packet.
		begin := time.Now()
		if _, err := p.WriteTo(wb, nil, dst); err != nil {
			fmt.Printf("error writing packet: %v\n", err)
			os.Exit(1)
		}

		// Wait for a reply.
		if err := p.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			fmt.Printf("error setting read deadline: %v\n", err)
			os.Exit(1)
		}
		n, _, peer, err := p.ReadFrom(rb)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				fmt.Printf("%d. * \n", i)
				continue
			}
			fmt.Printf("error reading packet: %v\n", err)
			os.Exit(1)
		}
		rtt := time.Since(begin)

		rm, err := icmp.ParseMessage(protocolICMP, rb[:n])
		if err != nil {
			fmt.Printf("error parsing ICMP message: %v\n", err)
			os.Exit(1)
		}

		switch rm.Type {
		case ipv4.ICMPTypeTimeExceeded:
			fmt.Printf("%d. %v %v\n", i, peer, rtt)
		case ipv4.ICMPTypeEchoReply:
			fmt.Printf("%d. %v %v\n", i, peer, rtt)
			return
		default:
			fmt.Printf("received unexpected ICMP message type: %v\n", rm.Type)
		}
	}
}

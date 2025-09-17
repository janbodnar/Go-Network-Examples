// This program is a simple ICMP ping tool. It sends an ICMP echo request
// to a host and waits for an echo reply.
//
// This program must be run as root.
//
// It requires the golang.org/x/net/icmp package:
// go get golang.org/x/net/icmp
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
	// The protocol number for ICMPv4 is 1.
	protocolICMP = 1
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <host>\n", os.Args[0])
		os.Exit(1)
	}

	host := os.Args[1]

	// Resolve the host to an IP address.
	addrs, err := net.LookupIP(host)
	if err != nil {
		fmt.Printf("could not get IPs for host %s: %v\n", host, err)
		os.Exit(1)
	}
	addr := addrs[0]

	// Create a raw socket connection.
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("error listening for ICMP packets: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Create an ICMP message.
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("hello"),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		fmt.Printf("error marshalling ICMP message: %v\n", err)
		os.Exit(1)
	}

	// Send the ICMP message.
	start := time.Now()
	if _, err := conn.WriteTo(msgBytes, &net.IPAddr{IP: addr}); err != nil {
		fmt.Printf("error writing ICMP message: %v\n", err)
		os.Exit(1)
	}

	// Wait for a reply.
	reply := make([]byte, 1500)
	err = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		fmt.Printf("error setting read deadline: %v\n", err)
		os.Exit(1)
	}
	n, peer, err := conn.ReadFrom(reply)
	if err != nil {
		fmt.Printf("error reading from ICMP connection: %v\n", err)
		os.Exit(1)
	}
	duration := time.Since(start)

	// Parse the reply.
	replyMsg, err := icmp.ParseMessage(protocolICMP, reply[:n])
	if err != nil {
		fmt.Printf("error parsing ICMP reply: %v\n", err)
		os.Exit(1)
	}

	switch replyMsg.Type {
	case ipv4.ICMPTypeEchoReply:
		fmt.Printf("received echo reply from %s in %v\n", peer, duration)
	default:
		fmt.Printf("received unexpected ICMP message type: %v from %s\n", replyMsg.Type, peer)
	}
}

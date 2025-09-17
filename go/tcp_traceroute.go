package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <host> <port>", os.Args[0])
	}
	host := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatalf("Invalid port: %v", err)
	}

	dstIPs, err := net.LookupIP(host)
	if err != nil {
		log.Fatalf("Could not get IPs for %s: %v", host, err)
	}
	dstIP := dstIPs[0].To4()
	if dstIP == nil {
		log.Fatalf("Not an IPv4 address: %s", dstIPs[0])
	}

	// This is the port we'll send from
	srcPort := layers.TCPPort(61000)

	fmt.Printf("Traceroute to %s (%s), %d hops max\n", host, dstIP, 64)

	for ttl := 1; ttl <= 64; ttl++ {
		// Create a raw socket for this TTL
		conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
		if err != nil {
			log.Fatal(err)
		}
		p := ipv4.NewPacketConn(conn)
		if err := p.SetTTL(ttl); err != nil {
			conn.Close()
			log.Fatal(err)
		}

		// Create the TCP packet
		tcpLayer := &layers.TCP{
			SrcPort: srcPort,
			DstPort: layers.TCPPort(port),
			SYN:     true,
			Seq:     1105024978,
			Window:  14600,
		}
		ipLayer := &layers.IPv4{
			SrcIP:    getOurIP(),
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP,
		}
		tcpLayer.SetNetworkLayer(ipLayer)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		if err := gopacket.SerializeLayers(buf, opts, tcpLayer); err != nil {
			log.Fatal(err)
		}

		// Send the packet
		if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstIP}); err != nil {
			log.Fatal(err)
		}

		// Read the response
		reply := make([]byte, 1500)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, addr, err := conn.ReadFrom(reply)
		if err != nil {
			fmt.Printf("%2d. *\n", ttl)
			continue
		}

		packet := gopacket.NewPacket(reply[:n], layers.LayerTypeIPv4, gopacket.Default)
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			if icmp.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded {
				fmt.Printf("%2d. %s\n", ttl, addr.String())
			}
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.DstPort == srcPort {
				if tcp.SYN && tcp.ACK {
					fmt.Printf("%2d. %s (reached)\n", ttl, addr.String())
					return
				} else if tcp.RST {
					fmt.Printf("%2d. %s (reset)\n", ttl, addr.String())
					return
				}
			}
		}
		conn.Close()
	}
}

func getOurIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

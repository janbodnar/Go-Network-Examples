# 100 Diagnostic & Utility Networking Examples

## Visibility & Scanning

This section covers tools for discovering network hosts, open ports, and  
services. These examples form the foundation of network mapping and security  
auditing.  

### TCP connect scanner

A TCP connect scanner attempts to complete a full three-way handshake with the
target port. It is reliable but easily detectable.

```go
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s <host> <start_port> <end_port>\n", os.Args[0])
		os.Exit(1)
	}

	host := os.Args[1]
	startPort, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Printf("Invalid start port: %s\n", os.Args[2])
		os.Exit(1)
	}
	endPort, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Printf("Invalid end port: %s\n", os.Args[3])
		os.Exit(1)
	}

	var wg sync.WaitGroup
	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", host, p)
			conn, err := net.DialTimeout("tcp", address, 1*time.Second)
			if err != nil {
				// Port is closed or filtered
				return
			}
			conn.Close()
			fmt.Printf("Port %d is open\n", p)
		}(port)
	}
	wg.Wait()
}
```

This Go program takes a host, a starting port, and an ending port as  
command-line arguments. It then scans the specified port range on the host.  
It uses goroutines for concurrency and a `sync.WaitGroup` to wait for all  
goroutines to finish. The `net.DialTimeout` function is used to attempt a  
connection with a timeout of one second. If a connection is successful, the  
port is reported as open.  

### TCP SYN scanner

A TCP SYN scanner sends a SYN packet and waits for a SYN-ACK to determine if a
port is open, avoiding a full connection. It is stealthier than a connect scan.

```go
// This program is a TCP SYN scanner. It sends a SYN packet to a range of ports
// on a target host and waits for a SYN-ACK response to determine if a port is 
// open. This is a "half-open" scan because it does not complete the TCP 
// three-way handshake.
//
// This program must be run as root.
//
// It requires the gopacket library:
// go get github.com/google/gopacket
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// getLocalIP returns the local IP address that will be used to send packets 
// to the destination.
func getLocalIP(dstip net.IP) (net.IP, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		return nil, err
	}
	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, nil
		}
	}
	return nil, fmt.Errorf("could not get local IP")
}

// scanner scans a range of ports on a host using a TCP SYN scan.
type scanner struct {
	host      string
	startPort int
	endPort   int
	timeout   time.Duration
	results   chan int
	wg        sync.WaitGroup
}

func newScanner(host string, startPort, endPort int, 
		timeout time.Duration) *scanner {
	return &scanner{
		host:      host,
		startPort: startPort,
		endPort:   endPort,
		timeout:   timeout,
		results:   make(chan int),
	}
}

func (s *scanner) run() {
	// Get the destination IP address.
	dstaddrs, err := net.LookupIP(s.host)
	if err != nil {
		log.Fatalf("could not get IPs for host %s: %v", s.host, err)
	}
	dstip := dstaddrs[0].To4()

	// Get the source IP address.
	srcip, err := getLocalIP(dstip)
	if err != nil {
		log.Fatalf("could not get local IP: %v", err)
	}

	// Start a listener to capture incoming packets.
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Start a worker goroutine to read packets.
	go s.readPackets(conn, srcip, dstip)

	// Send SYN packets to all ports in the range.
	for port := s.startPort; port <= s.endPort; port++ {
		s.wg.Add(1)
		go s.sendSYN(conn, dstip, layers.TCPPort(port))
	}

	s.wg.Wait()
	close(s.results)
}

func (s *scanner) sendSYN(conn net.PacketConn, dstip net.IP, 
		port layers.TCPPort) {
	defer s.wg.Done()

	// Our IP header... not used, but necessary for TCP checksumming.
	ip := &layers.IPv4{
		SrcIP:    conn.LocalAddr().(*net.IPAddr).IP,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}
	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: 54321, // A random source port
		DstPort: port,
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		log.Printf("error serializing layers: %v", err)
		return
	}

	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		log.Printf("error writing to connection: %v", err)
	}
}

func (s *scanner) readPackets(conn net.PacketConn, srcip, dstip net.IP) {
	for {
		b := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Printf("error reading from connection: %v", err)
			continue
		}

		if addr.String() == dstip.String() {
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.DstPort == 54321 {
					if tcp.SYN && tcp.ACK {
						s.results <- int(tcp.SrcPort)
					}
				}
			}
		}
		conn.Close()
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s <host> <start_port> <end_port>\n", os.Args[0])
		os.Exit(1)
	}

	host := os.Args[1]
	startPort, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Printf("Invalid start port: %s\n", os.Args[2])
		os.Exit(1)
	}
	endPort, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Printf("Invalid end port: %s\n", os.Args[3])
		os.Exit(1)
	}

	s := newScanner(host, startPort, endPort, 5*time.Second)
	go s.run()

	// Wait for results and print them.
	for port := range s.results {
		fmt.Printf("Port %d is open\n", port)
	}
}
```

This program sends a raw TCP SYN packet to each port in a given range. It then
listens for SYN-ACK responses to identify open ports. This technique is known as
a "half-open" scan because it doesn't complete the TCP handshake.

**Note:** This program requires root privileges to run and depends on the  
`gopacket` library. You can install it with `go get github.com/google/gopacket`.  

### UDP port scanner

A UDP port scanner sends a UDP packet to a target port. If an ICMP "port
unreachable" error is returned, the port is closed. Otherwise, it is assumed  
open.  

```go
// This program is a basic UDP port scanner. It sends a UDP packet to a range 
// of ports on a target host. If it doesn't receive an immediate "connection 
// refused" error, it considers the port to be open or filtered.
//
// Note: UDP scanning is inherently unreliable. A lack of response could mean 
// the port is open, or that the packet was lost, or that a firewall is 
// dropping it.
// A more advanced scanner would listen for ICMP "port unreachable" messages to
// definitively determine if a port is closed.
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s <host> <start_port> <end_port>\n", os.Args[0])
		os.Exit(1)
	}

	host := os.Args[1]
	startPort, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Printf("Invalid start port: %s\n", os.Args[2])
		os.Exit(1)
	}
	endPort, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Printf("Invalid end port: %s\n", os.Args[3])
		os.Exit(1)
	}

	var wg sync.WaitGroup
	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", host, p)
			// We use DialTimeout to avoid waiting forever on a port that doesn't respond.
			conn, err := net.DialTimeout("udp", address, 1*time.Second)
			if err != nil {
				// On some systems, a "connection refused" error will be returned for a closed UDP port.
				// However, this is not guaranteed.
				return
			}
			// If we get a connection object, we can't be sure the port is open,
			// but we know it's not immediately rejecting us.
			conn.Close()
			fmt.Printf("Port %d is open or filtered\n", p)
		}(port)
	}
	wg.Wait()
}
```

This program attempts to scan a range of UDP ports on a host. It uses
`net.DialTimeout` to send a UDP packet. If there's no immediate error (like
"connection refused"), it assumes the port is open or filtered.

**Note:** This is a very basic and often inaccurate way to scan UDP ports. A
proper UDP scanner needs to listen for ICMP "port unreachable" messages, which
requires raw sockets. This example is kept simple to demonstrate the basic
concept without adding the complexity of raw sockets.

### ICMP ping tool

An ICMP ping tool sends an ICMP echo request to a target host and waits for an
echo reply to determine reachability and round-trip time.

```go
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
```

This program sends an ICMP echo request to the specified host and waits for a
reply. It uses a raw socket to send and receive ICMP packets, which requires
root privileges. The `golang.org/x/net/icmp` package is used to construct and
parse the ICMP messages.

**Note:** This program requires root privileges to run and depends on the
`golang.org/x/net/icmp` package. You can install it with
`go get golang.org/x/net/icmp`.

### ICMP traceroute

An ICMP traceroute sends ICMP echo requests with increasing TTL values to map the
path to a destination host, identifying routers along the way.

```go
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
```

This program performs a traceroute by sending ICMP echo requests with increasing
TTL values. It starts with a TTL of 1 and increments it for each subsequent
request. When a router decrements the TTL to zero, it sends back an ICMP "Time
Exceeded" message, revealing its IP address. The program stops when it receives
an "Echo Reply" from the destination or reaches the maximum number of hops.

**Note:** This program requires root privileges to run and depends on the
`golang.org/x/net/icmp` and `golang.org/x/net/ipv4` packages.

### TCP traceroute

A TCP traceroute sends TCP SYN packets with increasing TTL values to trace a
path, often used to bypass firewalls that block ICMP.

### DNS resolver with fallback

A DNS resolver that queries a primary DNS server and falls back to a secondary
server if the first one fails, ensuring higher reliability.

```go
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s <domain> <primary_dns> <secondary_dns>\n", os.Args[0])
		os.Exit(1)
	}

	domain := os.Args[1]
	primaryDNS := os.Args[2]
	secondaryDNS := os.Args[3]

	// First, try the primary DNS server.
	fmt.Printf("Querying primary DNS server: %s\n", primaryDNS)
	ips, err := resolveWithServer(domain, primaryDNS)
	if err != nil {
		fmt.Printf("Primary DNS server failed: %v\n", err)
		fmt.Printf("Falling back to secondary DNS server: %s\n", secondaryDNS)
		// If the primary fails, try the secondary.
		ips, err = resolveWithServer(domain, secondaryDNS)
		if err != nil {
			fmt.Printf("Secondary DNS server also failed: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("IP addresses for %s:\n", domain)
	for _, ip := range ips {
		fmt.Println(ip)
	}
}

func resolveWithServer(domain, server string) ([]net.IP, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, "udp", server+":53")
		},
	}
	return resolver.LookupIP(context.Background(), "ip4", domain)
}
```

### DNS resolver with DoH

A DNS resolver that uses DNS-over-HTTPS (DoH) to encrypt DNS queries,
enhancing privacy and preventing eavesdropping.

### DNS resolver with DNSSEC

A DNS resolver that validates DNSSEC signatures to ensure the authenticity and
integrity of DNS responses, protecting against spoofing.

### DNS resolver with EDNS

A DNS resolver that uses Extension Mechanisms for DNS (EDNS) to support larger
message sizes and additional flags.

### DNS MX record lookup

A tool to query Mail Exchange (MX) records for a domain to find its mail
servers and their priority.

### DNS TXT record parser

A tool to query and parse Text (TXT) records, often used for SPF, DKIM, and
other domain verification purposes.

### DNS CNAME chain tracer

A tool that recursively follows a chain of Canonical Name (CNAME) records until
it finds the final A or AAAA record.

### DNS cache simulator

A local DNS cache that stores recent query results to reduce latency and
offload upstream DNS servers.

### DNS round-robin resolver

A resolver that cycles through multiple IP addresses returned in a DNS A record,
useful for basic load balancing.

### ARP scanner

An ARP scanner sends ARP requests on a local network to discover active hosts
and map their IP addresses to MAC addresses.

### IPv6 neighbor discovery tool

An IPv6 tool that uses the Neighbor Discovery Protocol (NDP) to find other
nodes on the same link and their link-layer addresses.

### Reverse DNS lookup

A tool that performs a reverse DNS (rDNS) lookup to find the domain name
associated with a given IP address.

### WHOIS query tool

A WHOIS client that queries a WHOIS server to retrieve registration information
for a domain name or IP address.

### GeoIP lookup tool

A tool that uses a GeoIP database to map an IP address to its geographical
location, such as country, city, and ISP.

### TCP traceroute

This tool performs a traceroute to a destination host and port by sending TCP SYN packets with increasing TTL values. It listens for ICMP "Time Exceeded" messages from routers along the path to discover the route.

```go
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
```

Note that this tool requires the `github.com/google/gopacket` and `golang.org/x/net/ipv4` packages and must be run with root privileges to create raw sockets.

---

## Latency & Performance

This section focuses on tools for measuring network performance, including latency,
jitter, and throughput. These are critical for diagnosing bottlenecks.

### HTTP latency tester

A tool that measures the time taken to complete an HTTP GET request, from
connection start to response end.

### HTTP latency histogram

A tool that collects multiple HTTP latency measurements and plots them as a
histogram to visualize the distribution.

### HTTP latency with concurrency

A tool that tests HTTP latency with multiple concurrent clients to simulate load
and measure server performance under pressure.

### TCP RTT measurement

A tool to measure the round-trip time (RTT) of a TCP connection by tracking the
time between sending a data segment and receiving an acknowledgment.

### TCP retransmission detector

A tool that monitors a TCP stream for retransmitted packets, which often
indicate network congestion or packet loss.

### TCP congestion window visualizer

A tool that tracks and plots the size of the TCP congestion window (cwnd) over
time to visualize how the congestion control algorithm behaves.

### TCP keep-alive tester

A tool to verify if a remote host responds to TCP keep-alive probes, preventing
idle connections from being dropped by NATs or firewalls.

### TCP half-open detector

A tool that detects half-open TCP connections where one side has closed the
connection without the other's knowledge.

### TCP zero-window probe

A tool that sends zero-window probes to a receiver whose TCP window is full,
waiting for it to become available for more data.

### TCP slow-start visualizer

A tool that visualizes the exponential growth of the TCP congestion window
during the slow-start phase.

### TCP window scaling tester

A tool to check if a remote host supports the TCP window scale option, which
allows for larger receive windows and better performance on high-latency links.

### TCP SACK simulator

A tool that simulates Selective Acknowledgment (SACK) to demonstrate how it
enables faster recovery from multiple packet losses.

### TCP delayed ACK analyzer

A tool that analyzes a packet capture to measure the effect of delayed ACKs on
TCP round-trip time and throughput.

### TCP fast retransmit demo

A tool that demonstrates the TCP fast retransmit mechanism, where a sender
retransmits a lost packet after receiving three duplicate ACKs.

### UDP jitter monitor

A tool that measures the variation in packet arrival times (jitter) for a UDP
stream, which is critical for real-time applications.

### UDP packet loss monitor

A tool that sends a sequence of UDP packets and detects gaps in the sequence
numbers to calculate the packet loss rate.

### UDP latency histogram

A tool that measures and plots a histogram of UDP packet latencies to visualize
the performance of a connection.

### ICMP latency monitor

A tool that continuously sends ICMP echo requests to monitor host reachability
and latency fluctuations over time.

### QUIC handshake latency tester

A tool to measure the time taken to complete a QUIC handshake, which is often
faster than a traditional TCP+TLS handshake.

### HTTP/2 stream latency tester

A tool that measures the latency of individual streams within an HTTP/2
connection, demonstrating its multiplexing capabilities.

---

## Packet Capture & Filtering

This section provides examples for capturing, filtering, and analyzing raw network
packets. These are essential for deep protocol analysis and troubleshooting.

### Raw packet sniffer

A basic tool that captures all raw packets on a network interface using a
promiscuous mode socket.

### Protocol filter (DNS only)

A packet sniffer that uses a filter to capture only DNS (port 53) traffic,
ignoring all other packets.

### Payload extractor

A tool that captures packets and extracts their application-layer payload, such
as the body of an HTTP request.

### Timestamped capture

A packet sniffer that records a high-precision timestamp for each captured
packet, essential for performance analysis.

### Flow reassembly

A tool that reassembles TCP segments or IP fragments into a coherent data stream,
reconstructing the original data flow.

### BPF filter example

A packet sniffer that uses a Berkeley Packet Filter (BPF) expression to perform
complex, kernel-level filtering.

### Per-interface capture

A tool that allows the user to select a specific network interface for packet
capture.

### Live packet visualization

A tool that provides a real-time visualization of captured packets, showing
protocols, source/destination IPs, and ports.

### TLS handshake decoder

A tool that captures and decodes the messages of a TLS handshake, such as the
ClientHello, ServerHello, and Certificate messages.

### HTTP header extractor

A tool that captures HTTP traffic and extracts specific headers, such as
`Host`, `User-Agent`, or custom headers.

### TCP stream reconstruction

A tool that reconstructs a full TCP stream from captured segments, allowing for
analysis of the application-layer data exchange.

### DNS query/response matcher

A tool that captures DNS traffic and matches queries to their corresponding
responses using the transaction ID.

### ICMP echo tracker

A tool that tracks ICMP echo requests and replies to monitor host reachability
and identify unmatched or timed-out pings.

### ARP resolution monitor

A tool that captures ARP requests and replies to monitor how IP addresses are
resolved to MAC addresses on the local network.

### VLAN tag parser

A tool that parses 802.1Q VLAN tags from Ethernet frames to identify the VLAN ID
and priority.

### IPv6 extension header parser

A tool that parses IPv6 extension headers, such as Hop-by-Hop Options or
Routing headers, to analyze their contents.

### TCP flag visualizer

A tool that visualizes TCP flags (SYN, ACK, FIN, RST) in a captured stream to
make connection states easier to understand.

### TCP sequence number tracker

A tool that tracks and plots TCP sequence numbers to visualize data flow and
detect issues like retransmissions or out-of-order packets.

### UDP checksum validator

A tool that captures UDP packets and recalculates the checksum to validate its
integrity and detect corruption.

### Fragmented packet reassembler

A tool that collects and reassembles fragmented IP packets to reconstruct the
original, full IP datagram.

---

## Interface & System Info

This section includes tools for querying local network interfaces and system
networking configurations.

### Interface enumerator

A tool that lists all available network interfaces on the system, along with
their names and flags.

### MAC address reader

A tool to retrieve the MAC (Media Access Control) address of a specific network
interface.

### MTU discovery

A tool that determines the Maximum Transmission Unit (MTU) of a network path by
sending packets with the "Don't Fragment" bit set.

### IP address fetcher

A tool that retrieves the IPv4 and IPv6 addresses associated with a specific
network interface.

### Link status monitor

A tool that monitors the status of a network link (up or down) and reports
changes in real-time.

### Bandwidth usage monitor

A tool that tracks the number of bytes sent and received on an interface to
calculate its current bandwidth usage.

### Packet drop counter

A tool that reads kernel statistics to report the number of dropped packets for a
specific network interface.

### Duplex mode checker

A tool that checks whether a network interface is operating in full-duplex or
half-duplex mode.

### Interface speed tester

A tool that queries the operating system to determine the link speed of a network
interface (e.g., 1 Gbps, 100 Mbps).

### DNS config reader

A tool that reads the system's DNS configuration, such as the list of configured
DNS servers in `/etc/resolv.conf`.

### Routing table reader

A tool that displays the system's IP routing table to show how packets are
directed to different networks.

### IPv6 support checker

A tool that checks if the local system has IPv6 enabled and has been assigned an
IPv6 address.

### Promiscuous mode toggler

A tool that enables or disables promiscuous mode on a network interface,
allowing it to capture all traffic on the link.

### Driver info fetcher

A tool that retrieves information about the network interface driver, such as its
name and version.

### Hardware offload checker

A tool that checks which TCP/IP processing tasks (e.g., checksum calculation)
are offloaded to the network hardware.

### Interface stats logger

A tool that periodically logs detailed statistics for a network interface, such
as packets sent/received and errors.

### Interface error rate monitor

A tool that monitors and calculates the error rate of a network interface by
comparing error counts to total packet counts.

### Interface uptime tracker

A tool that tracks how long a network interface has been active and in an "up"
state.

### Interface buffer overflow detector

A tool that monitors interface statistics for buffer overflows, which can
indicate performance problems.

### Interface queue length monitor

A tool that monitors the length of the transmit queue (txqueuelen) for a network
interface to diagnose potential congestion.

---

## NAT, Proxy & Connectivity

This section explores tools for navigating Network Address Translation (NAT),
testing proxies, and verifying internet connectivity.

### NAT type classifier

A tool that uses techniques like STUN to classify the type of NAT a user is
behind (e.g., full cone, restricted cone).

### NAT detection via STUN

A client that queries a STUN (Session Traversal Utilities for NAT) server to
discover its public IP address and NAT type.

### NAT hole punching demo

A demonstration of NAT hole punching, where two clients behind NATs establish a
direct peer-to-peer connection.

### NAT traversal via TURN

A client that uses a TURN (Traversal Using Relays around NAT) server to relay
traffic when a direct connection cannot be established.

### NAT mapping lifetime tester

A tool that measures how long a NAT mapping (public IP and port to private IP
and port) is kept alive by the router.

### NAT port prediction tool

A tool that attempts to predict the external port that a NAT will assign for an
outgoing connection, useful for some P2P protocols.

### NAT rebinding simulator

A tool that simulates a NAT rebinding attack, where a malicious website tricks a
browser into accessing a private network service.

### External IP discovery

A simple tool that connects to an external service to discover the client's
public IP address.

### UPnP port mapping tester

A tool that uses Universal Plug and Play (UPnP) to request a port mapping from a
router and verifies if it was successful.

### IPv6 connectivity tester

A tool that checks for end-to-end IPv6 connectivity by attempting to reach a
known IPv6-only host.

### Dual-stack reachability checker

A tool that checks if a host is reachable over both IPv4 and IPv6, essential for
diagnosing issues on dual-stack networks.

### VPN tunnel reachability tester

A tool that sends traffic through a VPN tunnel to verify that it is up and
correctly routing packets.

### Proxy detection via headers

A tool that inspects HTTP headers like `X-Forwarded-For` and `Via` to detect if a
request is being routed through a proxy.

### Transparent proxy detection

A tool that attempts to detect a transparent proxy by making a request to a host
that resolves to a private IP address.

### DNS leak tester

A tool that checks if DNS queries are being sent outside of a VPN tunnel, which
can compromise privacy.

### CDN edge latency tester

A tool that measures latency to multiple edge servers of a Content Delivery
Network (CDN) to find the optimal one.

### Firewall port reachability tester

A tool that attempts to connect to a specific port on a remote server to check
if it is blocked by a firewall.

### HTTP proxy tester

A client that sends an HTTP request through a configured proxy to verify that it
is working correctly.

### SOCKS5 proxy tester

A client that establishes a connection through a SOCKS5 proxy to test its
functionality.

### Tor exit node reachability tester

A tool that attempts to connect to a service through a specific Tor exit node to
verify its reachability and performance.

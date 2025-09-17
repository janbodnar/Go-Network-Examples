// This program is a TCP SYN scanner. It sends a SYN packet to a range of ports
// on a target host and waits for a SYN-ACK response to determine if a port is open.
// This is a "half-open" scan because it does not complete the TCP three-way handshake.
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

// getLocalIP returns the local IP address that will be used to send packets to the
// destination.
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

func newScanner(host string, startPort, endPort int, timeout time.Duration) *scanner {
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

func (s *scanner) sendSYN(conn net.PacketConn, dstip net.IP, port layers.TCPPort) {
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

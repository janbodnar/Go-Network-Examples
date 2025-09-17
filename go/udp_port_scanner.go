// This program is a basic UDP port scanner. It sends a UDP packet to a range of ports
// on a target host. If it doesn't receive an immediate "connection refused" error,
// it considers the port to be open or filtered.
//
// Note: UDP scanning is inherently unreliable. A lack of response could mean the
// port is open, or that the packet was lost, or that a firewall is dropping it.
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

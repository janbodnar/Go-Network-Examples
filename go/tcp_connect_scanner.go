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

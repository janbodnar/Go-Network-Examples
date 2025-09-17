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

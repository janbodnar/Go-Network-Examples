package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/songgao/water"
)

const (
	// The port for the VPN server to listen on.
	vpnPort = "8080"
	// The IP address for the TUN interface on the client.
	clientTunIP = "10.0.0.2/24"
	// The IP address for the TUN interface on the server.
	serverTunIP = "10.0.0.1/24"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <server|client>", os.Args[0])
	}

	mode := os.Args[1]
	switch mode {
	case "server":
		runServer()
	case "client":
		if len(os.Args) < 3 {
			log.Fatalf("Usage: %s client <server-ip>", os.Args[0])
		}
		serverIP := os.Args[2]
		runClient(serverIP)
	default:
		log.Fatalf("Unknown mode: %s", mode)
	}
}

// runServer starts the VPN server.
func runServer() {
	// Create a new TUN interface.
	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatalf("Failed to create TUN interface: %v", err)
	}
	defer iface.Close()

	fmt.Printf("TUN interface created: %s\n", iface.Name())

	// Configure the TUN interface with an IP address.
	if err := configureIP(iface.Name(), serverTunIP); err != nil {
		log.Fatalf("Failed to configure IP address: %v", err)
	}

	// Listen for incoming TCP connections.
	ln, err := net.Listen("tcp", ":"+vpnPort)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", vpnPort, err)
	}
	defer ln.Close()
	fmt.Printf("VPN server listening on port %s\n", vpnPort)

	// Accept a connection.
	conn, err := ln.Accept()
	if err != nil {
		log.Fatalf("Failed to accept connection: %v", err)
	}
	defer conn.Close()
	fmt.Printf("Client connected from %s\n", conn.RemoteAddr())

	// Start tunneling traffic.
	go io.Copy(conn, iface)
	io.Copy(iface, conn)
}

// runClient starts the VPN client.
func runClient(serverIP string) {
	// Create a new TUN interface.
	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatalf("Failed to create TUN interface: %v", err)
	}
	defer iface.Close()

	fmt.Printf("TUN interface created: %s\n", iface.Name())

	// Configure the TUN interface with an IP address.
	if err := configureIP(iface.Name(), clientTunIP); err != nil {
		log.Fatalf("Failed to configure IP address: %v", err)
	}

	// Connect to the VPN server.
	conn, err := net.Dial("tcp", serverIP+":"+vpnPort)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()
	fmt.Printf("Connected to VPN server at %s\n", serverIP)

	// Start tunneling traffic.
	go io.Copy(conn, iface)
	io.Copy(iface, conn)
}

// configureIP configures the IP address of a network interface.
func configureIP(ifaceName, ipCIDR string) error {
	cmd := exec.Command("ip", "addr", "add", ipCIDR, "dev", ifaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add IP address: %v", err)
	}

	cmd = exec.Command("ip", "link", "set", "up", "dev", ifaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	return nil
}

package main

import (
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func main() {
	// The host to connect to.
	host := "test.rebex.net:22"
	user := "demo"
	password := "password"

	// Configure the SSH client.
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		// In a real application, you should use a more secure HostKeyCallback.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect to the SSH server.
	conn, err := net.Dial("tcp", host)
	if err != nil {
		log.Fatalf("Failed to dial: %s", err)
	}
	defer conn.Close()

	// Perform the SSH handshake.
	c, chans, reqs, err := ssh.NewClientConn(conn, host, config)
	if err != nil {
		log.Fatalf("Failed to create client: %s", err)
	}
	defer c.Close()

	fmt.Printf("Connected to %s\n", host)
	fmt.Printf("Server version: %s\n", string(c.ServerVersion()))

	// The client is now ready to be used.
	// We can open channels and send requests.
	// For this example, we will just close the connection.

	// We need to service the requests and channels in the background.
	go ssh.DiscardRequests(reqs)
	go func() {
		for newChannel := range chans {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}()
}

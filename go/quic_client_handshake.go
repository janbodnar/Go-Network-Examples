package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"

	"github.com/lucas-clemente/quic-go"
)

func main() {
	// The QUIC server to connect to.
	// This is a public server provided by the quic-go project.
	addr := "quic.quic-go.dev:443"

	// Configure the TLS client.
	// QUIC always uses TLS 1.3.
	// We need to provide a list of ALPN protocols. For HTTP/3, this is "h3".
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // In a real application, you should verify the server's certificate.
		NextProtos:         []string{"h3"},
	}

	// Dial the QUIC server.
	sess, err := quic.DialAddr(addr, tlsConf, nil)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer sess.CloseWithError(0, "")

	fmt.Printf("Connected to %s\n", addr)
	fmt.Println("Handshake successful.")

	// The session is now ready to be used.
	// We can open streams and send data.
	// For this example, we will just close the session.

	// To demonstrate opening a stream:
	stream, err := sess.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	fmt.Println("Stream opened.")
	// You could now write to the stream, for example, to make an HTTP/3 request.
}

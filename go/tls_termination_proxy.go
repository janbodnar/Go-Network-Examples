package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"time"
	"crypto/tls"
)

const (
	proxyAddr  = "localhost:8443"
	backendAddr = "localhost:8080"
)

// generateSelfSignedCert creates a self-signed certificate and private key.
func generateSelfSignedCert() (key, cert []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"My Corp"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return keyOut, certOut, nil
}

func main() {
	log.Println("Starting TLS termination proxy...")

	// Generate a self-signed certificate.
	key, cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	// Create a TLS configuration.
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		log.Fatalf("Failed to load key pair: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	// Start a listener.
	listener, err := tls.Listen("tcp", proxyAddr, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()
	log.Printf("Proxy listening on %s", proxyAddr)

	for {
		// Accept a client connection.
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		// Handle the connection in a new goroutine.
		go func() {
			defer clientConn.Close()

			// Connect to the backend.
			backendConn, err := net.Dial("tcp", backendAddr)
			if err != nil {
				log.Printf("Failed to connect to backend: %v", err)
				return
			}
			defer backendConn.Close()

			log.Printf("Proxying from %s to %s", clientConn.RemoteAddr(), backendAddr)

			// Copy data between the client and backend.
			go io.Copy(backendConn, clientConn)
			io.Copy(clientConn, backendConn)
		}()
	}
}

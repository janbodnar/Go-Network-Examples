# Socket Fundamentals

## TCP echo server

This example demonstrates a basic TCP echo server that listens for incoming
connections and sends back any data it receives.

```go
package main

import (
	"io"
	"log"
	"net"
)

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalln("Unable to bind to port")
	}
	log.Println("Listening on 0.0.0.0:8080")
	for {
		conn, err := listener.Accept()
		log.Println("Received connection")
		if err != nil {
			log.Fatalln("Unable to accept connection")
		}
		go echo(conn)
	}
}

func echo(conn net.Conn) {
	defer conn.Close()
	if _, err := io.Copy(conn, conn); err != nil {
		log.Fatalln("Unable to read/write data")
	}
}
```

The server binds to port 8080 and enters an infinite loop to accept
new connections. Each connection is handled in a separate goroutine,
allowing for concurrent clients. The `echo` function uses `io.Copy` to
stream data from the client back to the client, effectively echoing it.
Error handling is included to manage connection and I/O issues.

## TCP echo client

This client connects to the TCP echo server, sends a message, and prints the
server's response to the console.

```go
package main

import (
	"io"
	"log"
	"net"
	"os"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatalln("Unable to connect to server")
	}
	defer conn.Close()
	log.Println("Connected to server")
	go func() {
		if _, err := io.Copy(os.Stdout, conn); err != nil {
			log.Println(err)
		}
	}()
	if _, err := io.Copy(conn, os.Stdin); err != nil {
		log.Fatalln("Connection error")
	}
}
```

The client establishes a TCP connection to `127.0.0.1:8080`. It then
concurrently copies data from the server to standard output and from
standard input to the server. This allows the user to type a message,
send it, and see the echoed response. The program terminates when the
connection is closed or an error occurs.

## UDP echo server

This example shows a UDP server that listens for packets and echoes them back
to the sender's address.

```go
package main

import (
	"log"
	"net"
)

func main() {
	socket, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 8080,
	})
	if err != nil {
		log.Fatalln("Unable to bind to port")
	}
	defer socket.Close()
	log.Println("Listening on 0.0.0.0:8080")
	buffer := make([]byte, 1024)
	for {
		n, addr, err := socket.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error reading from UDP:", err)
			continue
		}
		log.Printf("Received %d bytes from %s: %s", n, addr, buffer[:n])
		_, err = socket.WriteToUDP(buffer[:n], addr)
		if err != nil {
			log.Println("Error writing to UDP:", err)
		}
	}
}
```

The UDP server binds to port 8080 using `net.ListenUDP`. Unlike TCP, UDP is
connectionless, so the server reads packets into a buffer and receives the
sender's address. It then uses `WriteToUDP` to send the received data back
to the original sender. The loop continues indefinitely to handle multiple
clients.

## UDP echo client

This client sends a message to the UDP echo server and prints the response.

```go
package main

import (
	"log"
	"net"
)

func main() {
	conn, err := net.Dial("udp", "127.0.0.1:8080")
	if err != nil {
		log.Fatalln("Failed to connect to server", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("Hello UDP Server"))
	if err != nil {
		log.Fatalln("Failed to send message", err)
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatalln("Failed to read response", err)
	}

	log.Printf("Received: %s", buffer[:n])
}
```

The client uses `net.Dial` with the "udp" network type to establish a
connection. While UDP is connectionless, this gives a "connected" socket,
meaning it can only send to and receive from the specified server address.
The client sends a message, reads the response into a buffer, and prints
it to the console.

## Unix domain socket server

This server listens on a Unix domain socket, a file-system based IPC
mechanism for same-host communication.

```go
package main

import (
	"io"
	"log"
	"net"
	"os"
)

func main() {
	socketPath := "/tmp/echo.sock"
	os.Remove(socketPath) // Clean up previous socket file

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to listen on socket: %v", err)
	}
	defer listener.Close()

	log.Printf("Listening on %s", socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go echo(conn)
	}
}

func echo(conn net.Conn) {
	defer conn.Close()
	io.Copy(conn, conn)
}
```

The server uses `net.Listen` with the "unix" network type and a file path.
It's important to remove any old socket file before listening. The rest of
the logic is similar to the TCP echo server: it accepts connections in a
loop and handles each one in a goroutine. Unix sockets are often faster
than TCP loopback for inter-process communication on the same machine.

## Unix domain socket client

This client connects to the Unix domain socket server and exchanges data.

```go
package main

import (
	"io"
	"log"
	"net"
	"os"
)

func main() {
	socketPath := "/tmp/echo.sock"
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to connect to socket: %v", err)
	}
	defer conn.Close()

	log.Println("Connected to server")

	go func() {
		if _, err := io.Copy(os.Stdout, conn); err != nil {
			log.Println(err)
		}
	}()

	if _, err := io.Copy(conn, os.Stdin); err != nil {
		log.Fatalln("Connection error")
	}
}
```

The client uses `net.Dial` with the "unix" network type and the same socket
file path as the server. The I/O logic is identical to the TCP echo
client, demonstrating the protocol-agnostic nature of Go's `net.Conn`
interface. Data is copied from standard input to the socket and from the
socket to standard output.

## Raw socket packet sniffer

This example demonstrates how to use a raw socket to capture and inspect IP
packets. Note that this requires administrator/root privileges to run.

```go
package main

import (
	"log"
	"net"
	"os"

	"golang.org/x/net/ipv4"
)

func main() {
	// Note: This requires root/administrator privileges.
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		log.Fatalf("Failed to listen on raw socket: %v", err)
	}
	defer conn.Close()

	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		log.Fatalf("Failed to create raw connection: %v", err)
	}

	buffer := make([]byte, 65535)
	for {
		header, payload, _, err := rawConn.ReadFrom(buffer)
		if err != nil {
			log.Printf("Error reading from raw socket: %v", err)
			continue
		}
		log.Printf("Received packet from %s: version=%d, header length=%d, "+
			"protocol=%d, payload length=%d", header.Src, header.Version, 
			header.Len, header.Protocol, len(payload))
	}
}
```

This program listens for all incoming TCP packets on the machine using a raw
IP socket (`ip4:tcp`). The `golang.org/x/net/ipv4` package provides a
`RawConn` type that simplifies reading and parsing IPv4 headers. The code
reads packets in a loop, and for each packet, it logs the source address,
IP version, header length, protocol number, and payload size. This is a
foundational technique for building network monitoring and security tools.

## Non-blocking TCP client

This client attempts to connect to a server with a timeout, demonstrating a
non-blocking connection.

```go
package main

import (
	"log"
	"net"
	"time"
)

func main() {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := dialer.Dial("tcp", "127.0.0.1:8081") // Use a different port
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Println("Connection timed out")
		} else {
			log.Fatalf("Failed to connect: %v", err)
		}
		return
	}
	defer conn.Close()

	log.Println("Connected successfully!")
}
```

This client uses a `net.Dialer` with a `Timeout` of 5 seconds. If the
connection to `127.0.0.1:8081` is not established within this duration,
`dialer.Dial` returns a timeout error. This is a simple and effective way
to prevent a client from blocking indefinitely while trying to connect to
an unresponsive server. The code specifically checks for a timeout error
to provide a clear message.

## Non-blocking TCP server

This server demonstrates non-blocking I/O by setting deadlines on client
connections, preventing them from tying up server resources indefinitely.

```go
package main

import (
	"io"
	"log"
	"net"
	"time"
)

func main() {
	listener, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()
	log.Println("Listening on 0.0.0.0:8081")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("Handling new connection from %s", conn.RemoteAddr())

	for {
		// Set a deadline for the next read.
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Println("Read timeout, closing connection.")
				return
			}
			if err == io.EOF {
				log.Println("Connection closed by client.")
				return
			}
			log.Printf("Read error: %v", err)
			return
		}

		log.Printf("Received: %s", buffer[:n])
		conn.Write(buffer[:n]) // Echo back
	}
}
```

While Go's networking model is inherently concurrent, this example shows how to
make I/O operations non-blocking in a different sense. By calling
`SetReadDeadline`, the server ensures that a `conn.Read` call will not block
for more than 5 seconds. If no data is received in that time, a timeout
error is returned, and the server can close the connection. This prevents a
malicious or faulty client from holding a connection open forever.

## SSL/TLS TCP client

This example shows how to establish a secure TCP connection using TLS.

```go
package main

import (
	"crypto/tls"
	"fmt"
	"log"
)

func main() {
	// Connect to a public server that supports TLS, like Google.
	conn, err := tls.Dial("tcp", "google.com:443", &tls.Config{
		// In a real application, you would likely want to configure the
		// TLS client with specific root CAs, client certificates, etc.
		// For this example, we use a nil config for simplicity, which
		// uses the system's default CAs.
	})
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	log.Println("Connected to google.com:443")

	// Send a simple HTTP GET request.
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"))
	if err != nil {
		log.Fatalf("Failed to write to connection: %v", err)
	}

	// Read the response.
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Fatalf("Failed to read from connection: %v", err)
	}

	fmt.Printf("Received %d bytes:\n%s\n", n, buffer[:n])
}
```

This client uses `tls.Dial` to create a secure connection to `google.com` on
port 443. The `tls.Config` struct can be used to customize the TLS handshake,
such as by providing a set of trusted root certificate authorities. A `nil`
config uses the host's default trust store. After connecting, the client
sends a basic HTTP request and prints the first 4KB of the response,
demonstrating that the encrypted communication was successful.

## SSL/TLS TCP server

This server demonstrates how to create a secure TCP server that handles TLS  
connections with a self-signed certificate for testing purposes.

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"time"
)

func main() {
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", ":8443", config)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	log.Println("TLS server listening on :8443")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleTLSConnection(conn)
	}
}

func handleTLSConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("TLS connection from %s", conn.RemoteAddr())
	io.Copy(conn, conn) // Echo back
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template,
		&template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
```

This server creates a self-signed certificate at runtime and uses it to  
provide TLS encryption on port 8443. The `generateSelfSignedCert` function  
creates an RSA key pair and X.509 certificate valid for localhost. The  
server accepts TLS connections and echoes data back to clients. In  
production, you would use proper certificates from a certificate authority  
rather than self-signed ones.

## Multicast UDP sender

This sender demonstrates how to send UDP packets to a multicast address,  
allowing multiple receivers to receive the same data simultaneously.

```go
package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	multicastAddr := "224.0.0.1:9999"
	addr, err := net.ResolveUDPAddr("udp", multicastAddr)
	if err != nil {
		log.Fatalf("Failed to resolve multicast address: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatalf("Failed to dial multicast address: %v", err)
	}
	defer conn.Close()

	log.Printf("Sending to multicast group %s", multicastAddr)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	counter := 1
	for range ticker.C {
		message := fmt.Sprintf("Multicast message #%d", counter)
		_, err := conn.Write([]byte(message))
		if err != nil {
			log.Printf("Failed to send message: %v", err)
			continue
		}
		log.Printf("Sent: %s", message)
		counter++
	}
}
```

This sender joins the multicast group `224.0.0.1:9999` and sends periodic  
messages every 2 seconds. The address `224.0.0.1` is reserved for "All  
Systems" multicast in IPv4. The sender uses `net.DialUDP` to establish a  
connection to the multicast address, then sends numbered messages in a  
loop. Multiple receivers can join this multicast group to receive the  
same messages simultaneously, making it useful for broadcasting data  
to multiple clients efficiently.

## Multicast UDP receiver

This receiver joins a multicast group and listens for messages sent by  
multicast senders, demonstrating one-to-many communication.

```go
package main

import (
	"log"
	"net"

	"golang.org/x/net/ipv4"
)

func main() {
	multicastAddr := "224.0.0.1:9999"
	addr, err := net.ResolveUDPAddr("udp", multicastAddr)
	if err != nil {
		log.Fatalf("Failed to resolve multicast address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on multicast address: %v", err)
	}
	defer conn.Close()

	pc := ipv4.NewPacketConn(conn)
	defer pc.Close()

	// Join the multicast group
	intf, err := net.InterfaceByName("eth0") // Use appropriate interface
	if err != nil {
		// Try to find any available interface
		interfaces, _ := net.Interfaces()
		for _, i := range interfaces {
			if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
				intf = &i
				break
			}
		}
	}

	if intf != nil {
		err = pc.JoinGroup(intf, &net.UDPAddr{IP: net.ParseIP("224.0.0.1")})
		if err != nil {
			log.Printf("Failed to join multicast group: %v", err)
		} else {
			log.Printf("Joined multicast group on interface %s", intf.Name)
		}
	}

	log.Printf("Listening for multicast messages on %s", multicastAddr)

	buffer := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading multicast message: %v", err)
			continue
		}
		log.Printf("Received from %s: %s", addr, buffer[:n])
	}
}
```

This receiver listens on the multicast address `224.0.0.1:9999` and joins  
the multicast group using the `golang.org/x/net/ipv4` package. It  
automatically selects an available network interface or uses a specified  
one to join the group. Once joined, the receiver enters a loop to read  
multicast messages from any sender in the group. Multiple receivers can  
join the same group and all will receive the same messages, demonstrating  
the broadcast nature of multicast communication.

## TCP connection pooling client

This client demonstrates connection pooling to efficiently reuse TCP  
connections and reduce the overhead of establishing new connections.

```go
package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type ConnectionPool struct {
	address     string
	maxConns    int
	connections chan net.Conn
	mu          sync.Mutex
	closed      bool
}

func NewConnectionPool(address string, maxConns int) *ConnectionPool {
	return &ConnectionPool{
		address:     address,
		maxConns:    maxConns,
		connections: make(chan net.Conn, maxConns),
	}
}

func (p *ConnectionPool) Get() (net.Conn, error) {
	select {
	case conn := <-p.connections:
		// Test if connection is still alive
		conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
		buffer := make([]byte, 1)
		_, err := conn.Read(buffer)
		conn.SetReadDeadline(time.Time{})
		if err == nil {
			return conn, nil
		}
		conn.Close()
	default:
	}

	// Create new connection
	return net.Dial("tcp", p.address)
}

func (p *ConnectionPool) Put(conn net.Conn) {
	if conn == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		conn.Close()
		return
	}

	select {
	case p.connections <- conn:
	default:
		conn.Close() // Pool is full
	}
}

func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}
	p.closed = true

	close(p.connections)
	for conn := range p.connections {
		conn.Close()
	}
}

func main() {
	pool := NewConnectionPool("127.0.0.1:8080", 5)
	defer pool.Close()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := pool.Get()
			if err != nil {
				log.Printf("Worker %d: Failed to get connection: %v", id, err)
				return
			}

			// Use the connection
			message := fmt.Sprintf("Hello from worker %d", id)
			conn.Write([]byte(message))

			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			if err != nil {
				log.Printf("Worker %d: Read error: %v", id, err)
				conn.Close()
				return
			}

			log.Printf("Worker %d: Response: %s", id, buffer[:n])
			pool.Put(conn) // Return connection to pool
		}(i)
	}

	wg.Wait()
}
```

This example implements a simple connection pool that maintains a pool of  
TCP connections to reduce connection establishment overhead. The  
`ConnectionPool` struct manages up to `maxConns` connections in a buffered  
channel. The `Get` method retrieves an existing connection or creates a new  
one if none are available. It tests connection liveness before returning  
cached connections. The `Put` method returns connections to the pool for  
reuse. Multiple goroutines demonstrate concurrent usage of the pool,  
showing how connection pooling can improve performance in high-throughput  
applications.

## Rate-limited TCP server

This server demonstrates how to implement rate limiting to control the  
number of requests processed per time period, preventing resource exhaustion.

```go
package main

import (
	"io"
	"log"
	"net"
	"time"

	"golang.org/x/time/rate"
)

func main() {
	// Allow 10 requests per second with a burst of 20
	limiter := rate.NewLimiter(rate.Limit(10), 20)

	listener, err := net.Listen("tcp", ":8082")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	log.Println("Rate-limited server listening on :8082")
	log.Println("Rate limit: 10 requests/second, burst: 20")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleRateLimitedConnection(conn, limiter)
	}
}

func handleRateLimitedConnection(conn net.Conn, limiter *rate.Limiter) {
	defer conn.Close()
	log.Printf("Connection from %s", conn.RemoteAddr())

	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err == io.EOF {
				log.Printf("Connection closed by %s", conn.RemoteAddr())
				return
			}
			log.Printf("Read error from %s: %v", conn.RemoteAddr(), err)
			return
		}

		// Check rate limit before processing request
		if !limiter.Allow() {
			log.Printf("Rate limit exceeded for %s", conn.RemoteAddr())
			conn.Write([]byte("Rate limit exceeded. Please try again later.\n"))
			continue
		}

		// Process the request (echo in this case)
		log.Printf("Processing request from %s: %s", conn.RemoteAddr(), buffer[:n])
		
		// Simulate some processing time
		time.Sleep(100 * time.Millisecond)
		
		response := "Processed: " + string(buffer[:n])
		conn.Write([]byte(response))
	}
}
```

This server uses the `golang.org/x/time/rate` package to implement a token  
bucket rate limiter that allows 10 requests per second with a burst capacity  
of 20. Each incoming request is checked against the rate limiter using  
`limiter.Allow()`. If the rate limit is exceeded, the server sends an error  
message instead of processing the request. This prevents the server from  
being overwhelmed by too many requests and helps maintain stable  
performance. The rate limiter is shared across all connections, providing  
global rate limiting for the entire server.

## TCP proxy server

This server acts as a TCP proxy, forwarding traffic between clients and a  
backend server, useful for load balancing or traffic inspection.

```go
package main

import (
	"io"
	"log"
	"net"
	"sync"
)

func main() {
	proxyAddr := ":8083"
	targetAddr := "127.0.0.1:8080"

	listener, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		log.Fatalf("Failed to listen on proxy address: %v", err)
	}
	defer listener.Close()

	log.Printf("TCP proxy listening on %s, forwarding to %s",
		proxyAddr, targetAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept client connection: %v", err)
			continue
		}
		go handleProxy(clientConn, targetAddr)
	}
}

func handleProxy(clientConn net.Conn, targetAddr string) {
	defer clientConn.Close()
	log.Printf("New proxy connection from %s", clientConn.RemoteAddr())

	// Connect to target server
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	log.Printf("Connected to target %s", targetAddr)

	// Use WaitGroup to ensure both directions complete
	var wg sync.WaitGroup
	wg.Add(2)

	// Copy data from client to target
	go func() {
		defer wg.Done()
		defer targetConn.Close()
		bytes, err := io.Copy(targetConn, clientConn)
		if err != nil {
			log.Printf("Error copying client->target: %v", err)
		}
		log.Printf("Client->Target: %d bytes", bytes)
	}()

	// Copy data from target to client
	go func() {
		defer wg.Done()
		defer clientConn.Close()
		bytes, err := io.Copy(clientConn, targetConn)
		if err != nil {
			log.Printf("Error copying target->client: %v", err)
		}
		log.Printf("Target->Client: %d bytes", bytes)
	}()

	wg.Wait()
	log.Printf("Proxy connection from %s closed", clientConn.RemoteAddr())
}
```

This proxy server listens on port 8083 and forwards all traffic to a target  
server at `127.0.0.1:8080`. For each client connection, it establishes a  
connection to the target server and uses two goroutines to copy data  
bidirectionally using `io.Copy`. The `sync.WaitGroup` ensures both copy  
operations complete before closing the connections. This pattern is useful  
for implementing load balancers, reverse proxies, or network debugging  
tools. The proxy is transparent to both the client and server, simply  
relaying data between them.

## SOCKS5 proxy server

This server implements a basic SOCKS5 proxy that allows clients to connect  
to remote servers through the proxy, commonly used for network tunneling.

```go
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

func main() {
	listener, err := net.Listen("tcp", ":1080")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	log.Println("SOCKS5 proxy server listening on :1080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleSOCKS5(conn)
	}
}

func handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	// SOCKS5 authentication negotiation
	buffer := make([]byte, 256)
	n, err := conn.Read(buffer)
	if err != nil || n < 2 {
		log.Printf("Failed to read auth methods: %v", err)
		return
	}

	// Check version (should be 5)
	if buffer[0] != 0x05 {
		log.Printf("Unsupported SOCKS version: %d", buffer[0])
		return
	}

	// Respond with "no authentication required"
	conn.Write([]byte{0x05, 0x00})

	// Read connection request
	n, err = conn.Read(buffer)
	if err != nil || n < 4 {
		log.Printf("Failed to read connection request: %v", err)
		return
	}

	// Parse request
	if buffer[0] != 0x05 || buffer[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	var targetAddr string
	switch buffer[3] {
	case 0x01: // IPv4
		if n < 10 {
			conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return
		}
		ip := net.IPv4(buffer[4], buffer[5], buffer[6], buffer[7])
		port := binary.BigEndian.Uint16(buffer[8:10])
		targetAddr = fmt.Sprintf("%s:%d", ip, port)
	case 0x03: // Domain name
		if n < 5 {
			conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return
		}
		domainLen := int(buffer[4])
		if n < 5+domainLen+2 {
			conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return
		}
		domain := string(buffer[5 : 5+domainLen])
		port := binary.BigEndian.Uint16(buffer[5+domainLen : 5+domainLen+2])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// Connect to target
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetAddr, err)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer targetConn.Close()

	// Send success response
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	log.Printf("SOCKS5 tunnel established: %s -> %s",
		conn.RemoteAddr(), targetAddr)

	// Relay data bidirectionally
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, conn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, targetConn)
	}()

	wg.Wait()
}
```

This SOCKS5 proxy implements the basic SOCKS5 protocol for tunneling TCP  
connections. It handles the authentication negotiation (using no  
authentication), parses connection requests for IPv4 addresses and domain  
names, establishes connections to target servers, and relays data  
bidirectionally. The proxy supports both IP addresses and domain name  
resolution. SOCKS5 is commonly used for circumventing network restrictions  
and providing secure tunneling through intermediate servers.

## TCP keepalive client

This client demonstrates how to configure TCP keepalive settings to detect  
and handle dead connections automatically.

```go
package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Enable TCP keepalive
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		log.Fatalf("Connection is not a TCP connection")
	}

	err = tcpConn.SetKeepAlive(true)
	if err != nil {
		log.Printf("Failed to enable keepalive: %v", err)
	}

	err = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	if err != nil {
		log.Printf("Failed to set keepalive period: %v", err)
	}

	log.Println("Connected with TCP keepalive enabled (30s period)")

	// Set read/write timeouts
	err = tcpConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	if err != nil {
		log.Printf("Failed to set read deadline: %v", err)
	}

	// Send periodic messages to test the connection
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	go func() {
		buffer := make([]byte, 1024)
		for {
			n, err := tcpConn.Read(buffer)
			if err != nil {
				log.Printf("Read error: %v", err)
				return
			}
			log.Printf("Received: %s", buffer[:n])
		}
	}()

	counter := 1
	for range ticker.C {
		message := []byte(fmt.Sprintf("Keepalive test message #%d", counter))
		_, err := tcpConn.Write(message)
		if err != nil {
			log.Printf("Write error: %v", err)
			break
		}
		log.Printf("Sent message #%d", counter)
		counter++

		if counter > 20 { // Send 20 messages then exit
			break
		}
	}

	log.Println("Client finished")
}
```

This client connects to a server and enables TCP keepalive with a 30-second  
period. Keepalive probes are automatically sent by the operating system to  
detect if the connection is still alive. The client also sets read  
deadlines and sends periodic test messages. If the remote end becomes  
unreachable, the keepalive mechanism will eventually detect this and close  
the connection. This is essential for long-lived connections that might  
become stale due to network issues, firewalls, or server failures.

## Socket options configuration

This example demonstrates how to configure various socket options to control  
network behavior, performance, and reliability characteristics.

```go
package main

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
)

func main() {
	// Create a TCP listener
	listener, err := net.Listen("tcp", ":8084")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	// Get the underlying file descriptor for socket options
	tcpListener := listener.(*net.TCPListener)
	file, err := tcpListener.File()
	if err != nil {
		log.Fatalf("Failed to get file descriptor: %v", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// Set SO_REUSEADDR to allow address reuse
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		log.Printf("Failed to set SO_REUSEADDR: %v", err)
	} else {
		log.Println("Set SO_REUSEADDR")
	}

	// Set SO_REUSEPORT (Linux specific)
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, 0xf, 1) // SO_REUSEPORT
	if err != nil {
		log.Printf("Failed to set SO_REUSEPORT: %v", err)
	} else {
		log.Println("Set SO_REUSEPORT")
	}

	// Set TCP_NODELAY to disable Nagle's algorithm
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	if err != nil {
		log.Printf("Failed to set TCP_NODELAY: %v", err)
	} else {
		log.Println("Set TCP_NODELAY")
	}

	log.Println("Socket options configured, listening on :8084")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleSocketOptionsConnection(conn)
	}
}

func handleSocketOptionsConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("Connection from %s", conn.RemoteAddr())

	// Configure client connection options
	tcpConn := conn.(*net.TCPConn)

	// Enable TCP keepalive
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(30 * time.Second)

	// Set buffer sizes
	file, err := tcpConn.File()
	if err == nil {
		fd := int(file.Fd())
		
		// Set send buffer size (SO_SNDBUF)
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 65536)
		
		// Set receive buffer size (SO_RCVBUF)
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 65536)
		
		// Get current socket options
		sendBuf, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		recvBuf, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		
		log.Printf("Socket buffers - Send: %d, Receive: %d", sendBuf, recvBuf)
		file.Close()
	}

	// Echo server functionality
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}
		
		response := fmt.Sprintf("Echo: %s", buffer[:n])
		conn.Write([]byte(response))
	}
}
```

This example demonstrates configuring various socket options using system  
calls. It sets `SO_REUSEADDR` to allow port reuse, `SO_REUSEPORT` for  
load distribution, and `TCP_NODELAY` to disable Nagle's algorithm for  
low-latency communication. The server also configures per-connection  
options like keepalive settings and buffer sizes. Socket options provide  
fine-grained control over network behavior, allowing optimization for  
specific use cases like high-performance servers or real-time applications.

## TCP connection multiplexer

This server demonstrates connection multiplexing using Go's select statement  
to handle multiple connections concurrently without goroutines per connection.

```go
package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

type Connection struct {
	conn   net.Conn
	id     int
	buffer []byte
}

func main() {
	listener, err := net.Listen("tcp", ":8085")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	log.Println("TCP multiplexer listening on :8085")

	connections := make(map[int]*Connection)
	connID := 0
	
	// Channel for new connections
	newConn := make(chan net.Conn, 10)
	
	// Channel for connection data
	connData := make(chan struct {
		id   int
		data []byte
		err  error
	}, 100)
	
	// Channel for connection closures
	connClosed := make(chan int, 10)

	// Accept connections in a goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Accept error: %v", err)
				continue
			}
			newConn <- conn
		}
	}()

	// Main multiplexing loop
	for {
		select {
		case conn := <-newConn:
			connID++
			id := connID
			connections[id] = &Connection{
				conn:   conn,
				id:     id,
				buffer: make([]byte, 1024),
			}
			log.Printf("New connection %d from %s", id, conn.RemoteAddr())
			
			// Start reading from this connection
			go readFromConnection(id, conn, connData, connClosed)

		case data := <-connData:
			if conn, exists := connections[data.id]; exists {
				if data.err != nil {
					log.Printf("Connection %d error: %v", data.id, data.err)
					conn.conn.Close()
					delete(connections, data.id)
				} else {
					// Echo the data back
					response := fmt.Sprintf("Multiplexer echo [%d]: %s", data.id, data.data)
					conn.conn.Write([]byte(response))
					log.Printf("Connection %d: %s", data.id, data.data)
					
					// Continue reading
					go readFromConnection(data.id, conn.conn, connData, connClosed)
				}
			}

		case id := <-connClosed:
			if conn, exists := connections[id]; exists {
				log.Printf("Connection %d closed", id)
				conn.conn.Close()
				delete(connections, id)
			}

		case <-time.After(30 * time.Second):
			// Periodic maintenance - check connection count
			log.Printf("Active connections: %d", len(connections))
		}
	}
}

func readFromConnection(id int, conn net.Conn, dataChan chan struct {
	id   int
	data []byte
	err  error
}, closedChan chan int) {
	
	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	
	if err != nil {
		dataChan <- struct {
			id   int
			data []byte
			err  error
		}{id: id, data: nil, err: err}
		closedChan <- id
		return
	}
	
	dataChan <- struct {
		id   int
		data []byte
		err  error
	}{id: id, data: buffer[:n], err: nil}
}
```

This multiplexer handles multiple TCP connections using a single event loop  
with Go's select statement. Instead of creating a goroutine per connection,  
it uses channels to coordinate between connection acceptance, data reading,  
and connection management. The main loop selects between new connections,  
incoming data, connection closures, and periodic maintenance. This approach  
can be more efficient for servers handling many concurrent connections,  
as it reduces goroutine overhead and provides centralized connection  
management. The pattern is similar to event-driven servers in other  
languages.

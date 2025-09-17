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
		log.Printf("Received packet from %s: version=%d, header length=%d, protocol=%d, payload length=%d",
			header.Src, header.Version, header.Len, header.Protocol, len(payload))
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

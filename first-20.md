# Top 20 Go Networking Examples for Beginners

Here are 20 essential Go networking code examples to help students get started. Each example is self-contained and demonstrates a core networking concept in Go.

---

### 1. Simple TCP Echo Server

This server listens on a TCP port and echoes back any data it receives from a  
client.  

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
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	if _, err := io.Copy(conn, conn); err != nil {
		log.Fatalln("Unable to read/write data")
	}
}
```

The `net.Listen("tcp", ":8080")` function creates a TCP listener on port 8080.  
The empty host string means it will listen on all available interfaces  
(0.0.0.0). The main loop continuously calls `listener.Accept()` to wait for  
incoming connections. Each new connection is handled in a separate goroutine  
using `go handleConnection(conn)`, enabling the server to handle multiple  
clients concurrently. The `handleConnection` function uses `io.Copy(conn, conn)`  
which reads data from the connection and immediately writes it back, creating  
the echo behavior. The `defer conn.Close()` ensures the connection is properly  
closed when the function exits.  

---

### 2. Simple TCP Client

This client connects to the TCP server, sends a message, and prints the  
response.  

```go
package main

import (
	"io"
	"log"
	"net"
	"os"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		log.Fatalln("Unable to connect to server")
	}
	defer conn.Close()

	log.Println("Connected to server. Type 'exit' to quit.")
	go func() {
		if _, err := io.Copy(os.Stdout, conn); err != nil {
			log.Println(err)
		}
	}()
	if _, err := io.Copy(conn, os.Stdin); err != nil {
		log.Fatalln(err)
	}
}
```

The `net.Dial("tcp", "localhost:8080")` establishes a TCP connection to the  
server running on localhost port 8080. This client creates an interactive  
session where user input is sent to the server and responses are displayed.  
Two `io.Copy` operations run concurrently: one goroutine copies data from the  
server connection to stdout (displaying server responses), while the main  
thread copies data from stdin to the server connection (sending user input).  
This bidirectional communication continues until the user types 'exit' or  
an error occurs. The `defer conn.Close()` ensures the connection is properly  
closed when the function exits.  

---

### 3. Simple UDP Echo Server

A UDP server that listens for packets and echoes them back to the sender.  

```go
package main

import (
	"log"
	"net"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", ":8080")
	if err != nil {
		log.Fatalln(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalln(err)
	}
	defer conn.Close()
	log.Println("UDP server listening on :8080")

	buffer := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error reading from UDP:", err)
			continue
		}
		log.Printf("Received %d bytes from %s: %s\n", n, remoteAddr, string(buffer[:n]))

		_, err = conn.WriteToUDP(buffer[:n], remoteAddr)
		if err != nil {
			log.Println("Error writing to UDP:", err)
		}
	}
}
```

UDP is a connectionless protocol, unlike TCP which maintains persistent  
connections. The `net.ResolveUDPAddr("udp", ":8080")` resolves the UDP  
address, and `net.ListenUDP()` creates a UDP socket bound to port 8080.  
The server uses `ReadFromUDP()` to receive packets, which returns the  
received data, the number of bytes read, and the sender's address.  
`WriteToUDP()` sends the echo response back to the original sender using  
their address. The 1024-byte buffer limits the maximum packet size that  
can be processed. Error handling allows the server to continue running  
even if individual packet operations fail.  

---

### 4. Simple UDP Client

A UDP client that sends a message to the UDP server and waits for the echo.  

```go
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
)

func main() {
	serverAddr, err := net.ResolveUDPAddr("udp", "localhost:8080")
	if err != nil {
		log.Fatalln(err)
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Fatalln(err)
	}
	defer conn.Close()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter message to send: ")
	text, _ := reader.ReadString('\n')

	_, err = conn.Write([]byte(text))
	if err != nil {
		log.Println(err)
	}

	buffer := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		log.Println(err)
	}
	fmt.Printf("Echo from server: %s", string(buffer[:n]))
}
```

The UDP client uses `net.ResolveUDPAddr()` to resolve the server's address  
and `net.DialUDP()` to create a UDP connection. The second parameter `nil`  
means the operating system will choose a local address automatically.  
`bufio.NewReader(os.Stdin)` creates a buffered reader for user input, and  
`ReadString('\n')` reads until a newline character. The client sends the  
message using `conn.Write()` and then waits for the echo response with  
`ReadFromUDP()`. Unlike TCP, UDP doesn't guarantee delivery or ordering,  
making it faster but less reliable. The client assumes the server will  
respond, but in real applications, you might want to implement timeouts  
or retry logic.  

---

### 5. Basic HTTP Server

A simple HTTP server that responds with "Hello, World!".

```go
package main

import (
	"fmt"
	"log"
	"net/http"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World!")
}

func main() {
	http.HandleFunc("/", helloHandler)
	log.Println("HTTP server starting on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalln(err)
	}
}
```

---

### 6. HTTP Client (GET Request)

Makes a GET request to a public API and prints the response body.

```go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	resp, err := http.Get("https://jsonplaceholder.typicode.com/todos/1")
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(body))
}
```

---

### 7. HTTP Client (POST Request)

Makes a POST request with a JSON payload.

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	data := map[string]string{"title": "foo", "body": "bar", "userId": "1"}
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatalln(err)
	}

	resp, err := http.Post("https://jsonplaceholder.typicode.com/posts", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(body))
}
```

---

### 8. Parsing a URL

Demonstrates how to parse a URL string into its components.

```go
package main

import (
	"fmt"
	"log"
	"net/url"
)

func main() {
	rawURL := "https://example.com:8080/path/to/resource?key1=value1&key2=value2#fragment"
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Scheme:", parsedURL.Scheme)
	fmt.Println("Host:", parsedURL.Host)
	fmt.Println("Path:", parsedURL.Path)
	fmt.Println("Query:", parsedURL.RawQuery)
	fmt.Println("Fragment:", parsedURL.Fragment)
}
```

---

### 9. DNS Lookup

Resolves a domain name to its IP addresses.

```go
package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	domain := "google.com"
	ips, err := net.LookupIP(domain)
	if err != nil {
		log.Fatalf("Could not get IPs for %s: %v\n", domain, err)
	}

	for _, ip := range ips {
		fmt.Printf("%s. IN A %s\n", domain, ip.String())
	}
}
```

---

### 10. Concurrent TCP Server

A TCP server that handles multiple client connections concurrently using goroutines.

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
		log.Fatalln(err)
	}
	defer listener.Close()
	log.Println("Concurrent TCP server listening on :8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go handleClient(conn) // Handle each client in a new goroutine
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	log.Printf("Serving %s\n", conn.RemoteAddr().String())
	if _, err := io.Copy(conn, conn); err != nil {
		log.Println("Error during copy:", err)
	}
}
```

---

### 11. TCP Client with Timeout

Sets a read/write deadline on a TCP connection.

```go
package main

import (
	"log"
	"net"
	"time"
)

func main() {
	conn, err := net.Dial("tcp", "google.com:80")
	if err != nil {
		log.Fatalln(err)
	}
	defer conn.Close()

	// Set a 5-second deadline for the write operation
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"))
	if err != nil {
		log.Fatalln("Write error:", err)
	}

	// Set a 5-second deadline for the read operation
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		log.Fatalln("Read error:", err)
	}

	log.Println("Received response from server.")
}
```

---

### 12. Graceful HTTP Server Shutdown

Shows how to shut down an HTTP server gracefully, allowing active connections to finish.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	server := &http.Server{Addr: ":8080"}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // Simulate work
		fmt.Fprintln(w, "Hello, client!")
	})

	go func() {
		log.Println("Server is running on port 8080")
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}
```

---

### 13. Simple WebSocket Server

A basic WebSocket server that echoes messages back to the client.

```go
package main

import (
	"log"
	"net/http"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			log.Println(err)
			return
		}
		log.Printf("Received: %s", p)
		if err := conn.WriteMessage(messageType, p); err != nil {
			log.Println(err)
			return
		}
	}
}

func main() {
	http.HandleFunc("/echo", echoHandler)
	log.Println("WebSocket server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```
*Note: This example requires the `gorilla/websocket` package: `go get github.com/gorilla/websocket`*

---

### 14. Simple WebSocket Client

A client to connect to the WebSocket echo server.

```go
package main

import (
	"log"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	u := url.URL{Scheme: "ws", Host: "localhost:8080", Path: "/echo"}
	log.Printf("connecting to %s", u.String())

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer c.Close()

	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("read:", err)
				return
			}
			log.Printf("recv: %s", message)
		}
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case t := <-ticker.C:
			err := c.WriteMessage(websocket.TextMessage, []byte(t.String()))
			if err != nil {
				log.Println("write:", err)
				return
			}
		case <-interrupt:
			log.Println("interrupt")
			// Cleanly close the connection by sending a close message
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write close:", err)
				return
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}
```

---

### 15. File Transfer Server (TCP)

A server that sends a file to a connecting client.

```go
package main

import (
	"io"
	"log"
	"net"
	"os"
)

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go sendFile(conn)
	}
}

func sendFile(conn net.Conn) {
	defer conn.Close()
	file, err := os.Open("send.txt") // Create a file named send.txt
	if err != nil {
		log.Println(err)
		return
	}
	defer file.Close()

	_, err = io.Copy(conn, file)
	if err != nil {
		log.Println(err)
	}
	log.Println("File sent successfully")
}
```

---

### 16. File Transfer Client (TCP)

A client that receives a file from the server.

```go
package main

import (
	"io"
	"log"
	"net"
	"os"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	file, err := os.Create("received.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	_, err = io.Copy(file, conn)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("File received successfully")
}
```

---

### 17. UDP Broadcast

A server that broadcasts a message to all devices on the local network.

```go
package main

import (
	"log"
	"net"
	"time"
)

func main() {
	conn, err := net.Dial("udp", "255.255.255.255:8080")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

_	for {
		message := "Hello, network!"
		conn.Write([]byte(message))
		log.Println("Broadcasted message:", message)
		time.Sleep(2 * time.Second)
	}
}
```

---

### 18. Basic TCP Port Scanner

A simple tool to check if specific ports are open on a host.

```go
package main

import (
	"fmt"
	"net"
	"sync"
)

func main() {
	host := "localhost"
	var wg sync.WaitGroup

	for port := 1; port <= 1024; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", host, p)
			conn, err := net.Dial("tcp", address)
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
```

---

### 19. HTTP Server with Routing

An HTTP server that uses `http.ServeMux` to handle different URL paths.

```go
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Welcome to the home page!")
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "This is the about page.")
	})
	mux.HandleFunc("/contact", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Contact us at support@example.com.")
	})

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
```

---

### 20. Using context.Context in an HTTP Server

Demonstrates how to use `context` to handle request cancellation.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/data", dataHandler)
	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log.Println("Handler started")
	defer log.Println("Handler finished")

	select {
	case <-time.After(5 * time.Second):
		// Simulate a long-running task
		fmt.Fprintln(w, "Data processed successfully")
	case <-ctx.Done():
		// This case is selected if the client cancels the request
		log.Println("Request cancelled by client")
		http.Error(w, "Request cancelled", http.StatusRequestTimeout)
	}
}
```

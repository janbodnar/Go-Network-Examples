# Top 20 Go Networking Examples for Beginners (Continued)

This file continues from `first-20.md` with more advanced Go networking
examples.

---

### 21. HTTP Middleware (Logging)

Middleware wraps an HTTP handler to provide pre- and post-processing, such as
logging, authentication, or compression.

```go
package main

import (
	"log"
	"net/http"
	"time"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Started %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
		log.Printf("Completed %s in %v", r.URL.Path, time.Since(start))
	})
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, from behind the middleware!"))
}

func main() {
	http.Handle("/", loggingMiddleware(http.HandlerFunc(helloHandler)))
	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

Middleware is a powerful pattern for composing reusable HTTP logic. The
`loggingMiddleware` function takes an `http.Handler` and returns a new one.
The returned handler logs the request path and method, calls the original
handler's `ServeHTTP` method, and then logs the request completion time.
This creates a chain of handlers. The `http.HandlerFunc` adapter is used to
convert a regular function into an `http.Handler`. This example demonstrates
how to add functionality to an HTTP server without modifying the core
business logic of the handlers themselves.

---

### 22. Serving Static Files

An HTTP server that serves static files (e.g., HTML, CSS, JS) from a local
directory.

```go
package main

import (
	"log"
	"net/http"
)

func main() {
	// Create a file server handler to serve files from the "static" directory
	fs := http.FileServer(http.Dir("./static"))

	// Register the file server handler for all requests starting with "/static/"
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// A simple handler for the root path
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Go to /static/ to see the file server in action."))
	})

	log.Println("Serving static files on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```
*Note: Create a directory named `static` and place some files in it to test this example.*

Go's `net/http` package provides a built-in file server. `http.Dir("./static")`
creates a virtual file system from the "static" directory. `http.FileServer`
returns a handler that serves files from this file system. `http.StripPrefix`
is a crucial adapter that removes the "/static/" prefix from the request URL
before passing it to the file server. For example, a request for
`/static/index.html` becomes a request for `/index.html` on the file system,
allowing the file server to find it correctly. This is the standard way to
serve static assets for a web application.

---

### 23. JSON Decoding in a Handler

A handler that decodes a JSON request body into a Go struct.

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var u User
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "Received user: %+v\n", u)
}

func main() {
	http.HandleFunc("/user", userHandler)
	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```
*To test, send a POST request with a JSON body: `curl -X POST -d '{"name":"John Doe","email":"john.doe@example.com"}' http://localhost:8080/user`*

This example shows how to process structured data sent to a server.
`json.NewDecoder(r.Body)` creates a decoder that reads from the request body.
The `Decode(&u)` method parses the JSON data and populates the fields of the
`User` struct `u`. The `json:"..."` struct tags map JSON keys to struct
fields, even if their names differ. This approach is efficient because it
decodes the stream directly without loading the entire body into memory first.
Proper error handling checks the request method and reports bad requests if
JSON parsing fails. This is fundamental for building REST APIs that accept
JSON payloads.

---

### 24. Custom HTTP Client Transport

An HTTP client with custom transport settings for controlling connection
behavior, such as timeouts.

```go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	transport := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second, // Overall request timeout
	}

	resp, err := client.Get("https://jsonplaceholder.typicode.com/todos/1")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(body))
}
```

The default `http.Client` is convenient but offers limited control. For
production use, you should create a custom client. `http.Transport` is the
core of the client, managing connections. `MaxIdleConns` controls the number
of idle connections in the pool, while `IdleConnTimeout` determines how long
they are kept alive. `DisableCompression` can be useful for debugging. The
`client.Timeout` sets a total timeout for the entire request, including
connection, redirects, and reading the body. Customizing the transport and
client provides fine-grained control over network behavior, which is essential
for building resilient and performant applications.

---

### 25. Simple RPC Server

A server that exposes Go methods for remote procedure calls (RPC) using the
built-in `net/rpc` package.

```go
package main

import (
	"log"
	"net"
	"net/rpc"
)

type Arith int

type Args struct {
	A, B int
}

func (t *Arith) Multiply(args *Args, reply *int) error {
	*reply = args.A * args.B
	return nil
}

func main() {
	arith := new(Arith)
	rpc.Register(arith)

	listener, err := net.Listen("tcp", ":1234")
	if err != nil {
		log.Fatal("listen error:", err)
	}
	defer listener.Close()

	log.Println("RPC server listening on port 1234")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("accept error:", err)
			continue
		}
		go rpc.ServeConn(conn)
	}
}
```

Go's `net/rpc` package provides a simple way to create RPC services.
An object's methods can be exposed if they are exported (start with a capital
letter), have two arguments (the first being arguments from the client, the
second a pointer for the reply), and have a return type of `error`.
`rpc.Register()` makes the methods of an object available for remote access.
The server listens on a TCP port and calls `rpc.ServeConn` for each incoming
connection, which handles the RPC protocol exchange. This is a simple,
Go-specific way to build services without the complexity of REST or gRPC.

---

### 26. Simple RPC Client

A client that connects to the RPC server and calls a remote method.

```go
package main

import (
	"log"
	"net/rpc"
)

type Args struct {
	A, B int
}

func main() {
	client, err := rpc.Dial("tcp", "localhost:1234")
	if err != nil {
		log.Fatal("dialing:", err)
	}
	defer client.Close()

	args := &Args{7, 8}
	var reply int
	err = client.Call("Arith.Multiply", args, &reply)
	if err != nil {
		log.Fatal("arith error:", err)
	}
	log.Printf("Arith: %d*%d=%d\n", args.A, args.B, reply)
}
```

The RPC client uses `rpc.Dial()` to connect to the server. The `client.Call()`
method invokes a remote procedure. The first argument is a string of the
form "TypeName.MethodName". The second argument is the parameters to be sent
to the remote method, and the third is a pointer where the result will be
stored. The client blocks until the remote call completes and the reply is
received. `net/rpc` handles the serialization of data (using the `gob`
package by default) and the network communication, making it easy to call
Go functions running on a different machine.

---

### 27. Broadcasting to WebSocket Clients

A WebSocket server that broadcasts a message to all connected clients, forming
a simple chat or notification system.

```go
package main

import (
	"log"
	"net/http"
	"sync"
	"github.com/gorilla/websocket"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	clients   = make(map[*websocket.Conn]bool)
	broadcast = make(chan []byte)
	mutex     = &sync.Mutex{}
)

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ws.Close()
	mutex.Lock()
	clients[ws] = true
	mutex.Unlock()

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			mutex.Lock()
			delete(clients, ws)
			mutex.Unlock()
			break
		}
		broadcast <- msg
	}
}

func handleMessages() {
	for {
		msg := <-broadcast
		mutex.Lock()
		for client := range clients {
			err := client.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				client.Close()
				delete(clients, client)
			}
		}
		mutex.Unlock()
	}
}

func main() {
	http.HandleFunc("/ws", handleConnections)
	go handleMessages()
	log.Println("WebSocket broadcast server started on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
```

This example builds on the basic WebSocket server by adding broadcast
functionality. A shared map `clients` stores all active connections. A mutex
is used to protect concurrent access to this map. When a message is received
from any client, it is sent to the `broadcast` channel. A dedicated goroutine
`handleMessages` reads from this channel and iterates over all connected
clients, sending the message to each one. This architecture decouples message
receiving from broadcasting, making the system more organized and scalable.
It also handles client disconnections by removing them from the pool.

---

### 28. HTTP/2 Server Push

An HTTP/2 server that proactively "pushes" resources to the client that it
knows the client will need.

```go
package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if pusher, ok := w.(http.Pusher); ok {
			// Push is supported.
			if err := pusher.Push("/static/style.css", nil); err != nil {
				log.Printf("Failed to push: %v", err)
			}
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<link rel="stylesheet" href="/static/style.css"><h1>Hello</h1>`))
	})

	http.HandleFunc("/static/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write([]byte("h1 { color: red; }"))
	})

	log.Println("Starting HTTP/2 server on :8443")
	// HTTP/2 is enabled automatically by ListenAndServeTLS
	err := http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
}
```
*Note: You need to generate a self-signed certificate for this: `go run $(go env GOROOT)/src/crypto/tls/generate_cert.go --host localhost`*

Server Push is a feature of HTTP/2 that allows the server to send resources
to the client before the client explicitly requests them. This can improve
load times by reducing the number of round trips. Go's HTTP server supports
this via the `http.Pusher` interface. The handler checks if the `ResponseWriter`
implements this interface. If so, it calls `pusher.Push()` to send the CSS
file along with the initial HTML response. When the browser parses the HTML
and sees the `<link>` tag, the CSS file will already be in its cache.
`ListenAndServeTLS` is required because browsers only support HTTP/2 over
encrypted connections (TLS).

---

### 29. Streaming an HTTP Response

A server that streams a large response body to the client, useful for sending
large amounts of data without high memory usage.

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func streamHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	for i := 1; i <= 10; i++ {
		fmt.Fprintf(w, "Chunk %d\n", i)
		flusher.Flush() // Send the chunk to the client
		time.Sleep(500 * time.Millisecond)
	}
}

func main() {
	http.HandleFunc("/stream", streamHandler)
	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

By default, Go's HTTP server buffers the response body before sending it.
For large or slow-generating responses, it's better to stream the data.
The `http.Flusher` interface allows a handler to send buffered data to the
client immediately. The handler first checks if the `ResponseWriter` supports
flushing. Inside the loop, it writes a chunk of data and then calls
`flusher.Flush()`. This sends the data over the wire without waiting for the
handler to complete. This technique is ideal for long-polling, server-sent
events (SSE), or transmitting large datasets.

---

### 30. Handling Cookies

An HTTP server that demonstrates setting and reading cookies.

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func setCookieHandler(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:    "session_token",
		Value:   "some_secret_value",
		Expires: time.Now().Add(24 * time.Hour),
	}
	http.SetCookie(w, &cookie)
	fmt.Fprintln(w, "Cookie has been set!")
}

func getCookieHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "No cookie found", http.StatusNotFound)
			return
		}
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Cookie value: %s\n", cookie.Value)
}

func main() {
	http.HandleFunc("/set", setCookieHandler)
	http.HandleFunc("/get", getCookieHandler)
	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

Cookies are a common mechanism for session management and storing state on
the client side. `http.SetCookie()` adds a `Set-Cookie` header to the HTTP
response, instructing the browser to store the cookie. The `http.Cookie`
struct includes fields for name, value, expiration, path, and domain.
`r.Cookie("session_token")` retrieves a cookie from the `Cookie` header of
an incoming request. It returns `http.ErrNoCookie` if the cookie is not
present. This example provides two endpoints: one to set a cookie and another
to read it, demonstrating a basic stateful interaction over the stateless
HTTP protocol.

---

### 31. Mutual TLS (mTLS) Server

A server that requires clients to present a valid certificate for
authentication, in addition to the server presenting its own.

```go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello, client with a valid certificate!")
}

func main() {
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	server := &http.Server{
		Addr:      ":8443",
		Handler:   http.HandlerFunc(helloHandler),
		TLSConfig: tlsConfig,
	}

	log.Println("Starting mTLS server on :8443")
	err = server.ListenAndServeTLS("server.crt", "server.key")
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
}
```
*Note: This requires a CA, server, and client certificates. OpenSSL can be used to generate them.*

Mutual TLS (mTLS) enhances security by requiring both server and client to
prove their identities via certificates. The server loads the Certificate
Authority (CA) certificate that signed the client certificates. `tls.Config`
is configured with this CA pool and `ClientAuth` is set to
`tls.RequireAndVerifyClientCert`. This tells the server to reject any client
that doesn't present a certificate signed by the trusted CA. This is common
in service-to-service communication within a secure infrastructure.

---

### 32. Mutual TLS (mTLS) Client

A client that authenticates itself to an mTLS server using its own certificate
and key.

```go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		log.Fatal(err)
	}

	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(body))
}
```

The mTLS client configures its `http.Transport` with a custom `tls.Config`.
`tls.LoadX509KeyPair` loads the client's own certificate and private key.
The `RootCAs` field is set to the CA pool containing the server's CA, so the
client can verify the server's certificate. The `Certificates` field is set
to the client's own certificate, which will be sent to the server for
authentication during the TLS handshake. This ensures secure, two-way
authenticated communication.

---

### 33. Simple Reverse Proxy

A server that forwards incoming requests to another backend server.

```go
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	target, err := url.Parse("http://localhost:8081")
	if err != nil {
		log.Fatal(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Forwarding request to %s", target)
		proxy.ServeHTTP(w, r)
	})

	log.Println("Reverse proxy running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```
*Note: Run a backend server on port 8081 (e.g., any of the previous HTTP server examples) to test this.*

A reverse proxy acts as an intermediary for requests from clients to backend
servers. It's useful for load balancing, SSL termination, and caching.
`httputil.NewSingleHostReverseProxy` creates a proxy that forwards all
requests to a single target URL. The handler simply calls the proxy's
`ServeHTTP` method, which takes care of rewriting headers (like `Host`) and
copying the request and response bodies. This simple but powerful tool can
be the foundation for building sophisticated API gateways or load balancers.

---

### 34. gRPC Server

A basic gRPC server for high-performance, cross-platform RPC.

```go
// greet.proto
// syntax = "proto3";
// package greet;
// option go_package = "greetpb";
//
// service Greeter {
//   rpc SayHello (HelloRequest) returns (HelloReply) {}
// }
//
// message HelloRequest {
//   string name = 1;
// }
//
// message HelloReply {
//   string message = 1;
// }

package main

import (
	"context"
	"log"
	"net"
	"google.golang.org/grpc"
	"path/to/your/greetpb" // Replace with your actual path
)

type server struct{
	greetpb.UnimplementedGreeterServer
}

func (s *server) SayHello(ctx context.Context, in *greetpb.HelloRequest) (*greetpb.HelloReply, error) {
	return &greetpb.HelloReply{Message: "Hello " + in.Name}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	greetpb.RegisterGreeterServer(s, &server{})
	log.Println("gRPC server listening on :50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
```
*Note: This requires `protoc` and `protoc-gen-go` to generate code from the `.proto` file.*

gRPC is a modern RPC framework developed by Google. It uses Protocol Buffers
(`.proto` files) to define service interfaces and data structures. This results
in strongly-typed, efficient communication. The server implements the service
interface generated from the proto file. `grpc.NewServer()` creates a new gRPC
server instance. `greetpb.RegisterGreeterServer` registers the implementation.
The server listens on a TCP port and `s.Serve()` starts handling requests.
gRPC is ideal for microservices due to its performance, streaming support, and
language-agnostic nature.

---

### 35. gRPC Client

A client to interact with the gRPC server.

```go
package main

import (
	"context"
	"log"
	"time"
	"google.golang.org/grpc"
	"path/to/your/greetpb" // Replace with your actual path
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := greetpb.NewGreeterClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := c.SayHello(ctx, &greetpb.HelloRequest{Name: "World"})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %s", r.Message)
}
```

The gRPC client connects to the server using `grpc.Dial`. `grpc.WithInsecure()`
is used here for simplicity; production applications should use TLS.
`greetpb.NewGreeterClient()` creates a client stub from the connection.
The client can then call the service methods defined in the proto file as if
they were local methods (e.g., `c.SayHello`). The context is passed along
to handle timeouts and cancellation. gRPC's code generation makes client-side
development straightforward and type-safe.

---

### 36. ICMP Ping

Sends an ICMP Echo Request and waits for a reply, similar to the `ping` command.

```go
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <host>")
	}
	host := os.Args[1]

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("ListenPacket failed: %v", err)
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := c.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(host)}); err != nil {
		log.Fatalf("WriteTo failed: %v", err)
	}

	rb := make([]byte, 1500)
	n, _, err := c.ReadFrom(rb)
	if err != nil {
		log.Fatal(err)
	}
	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
	if err != nil {
		log.Fatal(err)
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		log.Printf("Got reply from %s", host)
	default:
		log.Printf("Got %+v; expected echo reply", rm)
	}
}
```
*Note: This program may require root privileges to create raw sockets.*

This example demonstrates low-level networking by implementing a ping client.
It uses the `golang.org/x/net/icmp` package to construct and parse ICMP
messages. `icmp.ListenPacket("ip4:icmp", ...)` creates a raw socket to listen
for ICMP traffic. An ICMP Echo message is created, marshaled into bytes, and
sent to the target host. The program then waits for a reply, parses it, and
verifies that it's an Echo Reply. This shows how to interact with network
protocols below the transport layer (TCP/UDP).

---

### 37. Rate Limiting HTTP Requests

An HTTP server that limits the number of requests a client can make in a
certain time period.

```go
package main

import (
	"log"
	"net/http"
	"golang.org/x/time/rate"
)

var limiter = rate.NewLimiter(1, 3) // 1 request per second, burst of 3

func limitedHandler(w http.ResponseWriter, r *http.Request) {
	if !limiter.Allow() {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}
	w.Write([]byte("Success!"))
}

func main() {
	http.HandleFunc("/", limitedHandler)
	log.Println("Server with rate limiting started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```
*Note: Requires `golang.org/x/time/rate`.*

Rate limiting is essential for protecting services from abuse and overload.
The `golang.org/x/time/rate` package provides a token bucket rate limiter.
`rate.NewLimiter(1, 3)` creates a limiter that replenishes one token per
second and allows a burst of up to 3 requests. In the handler, `limiter.Allow()`
checks if a request can be served. If not, it returns `false`, and the server
responds with an HTTP 429 status code. This is a simple and effective way to
control traffic to your server. More complex implementations might use a map
of limiters for per-IP rate limiting.

---

### 38. Custom DNS Resolver

Using a specific DNS server to resolve a domain name instead of the system's
default resolver.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			// Use Google's public DNS server
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	ips, err := resolver.LookupIPAddr(context.Background(), "google.com")
	if err != nil {
		log.Fatalf("Could not get IPs: %v\n", err)
	}

	for _, ip := range ips {
		fmt.Printf("google.com. IN A %s\n", ip.String())
	}
}
```

By default, Go uses the system's DNS settings. This example shows how to
create a custom DNS resolver that uses a specific DNS server (in this case,
Google's 8.8.8.8). The `net.Resolver` struct's `Dial` field can be set to a
custom function that establishes the connection to the DNS server. `PreferGo`
ensures the Go-native resolver is used. This is useful for testing, bypassing
local DNS issues, or querying internal DNS servers from an external network.
It gives you full control over how domain names are resolved in your
application.

---

### 39. Network Packet Sniffing

Capturing and inspecting network packets on a network interface.

```go
package main

import (
	"fmt"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		fmt.Println("--- Packet Captured ---")
		fmt.Println(packet)
	}
}
```
*Note: Requires `libpcap` to be installed on the system and may require root privileges. Replace "eth0" with your network interface.*

Packet sniffing involves capturing raw data packets from a network interface.
The `gopacket` library provides a powerful Go wrapper around `libpcap`.
`pcap.OpenLive` opens a network interface for capturing traffic.
`gopacket.NewPacketSource` creates a channel that delivers captured packets.
The program then ranges over this channel, printing each packet. `gopacket`
can decode many different network layers (Ethernet, IP, TCP, etc.), allowing
for deep inspection of network traffic. This is useful for network analysis,
debugging, and security monitoring tools.

---

### 40. Simple SSH Client

A client that connects to an SSH server and executes a remote command.

```go
package main

import (
	"bytes"
	"log"
	"golang.org/x/crypto/ssh"
)

func main() {
	config := &ssh.ClientConfig{
		User: "user", // Replace with your username
		Auth: []ssh.AuthMethod{
			ssh.Password("password"), // Replace with your password
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Insecure, use for testing only
	}

	client, err := ssh.Dial("tcp", "localhost:22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run("/bin/ls -l"); err != nil {
		log.Fatal("Failed to run: " + err.Error())
	}
	log.Println(b.String())
}
```
*Note: Requires `golang.org/x/crypto/ssh` and an SSH server to connect to.*

Go's `crypto/ssh` package provides a full-featured SSH client implementation.
The `ssh.ClientConfig` struct is used to configure the username, authentication
method (password-based here, but key-based is recommended for production), and
host key verification policy. `ssh.InsecureIgnoreHostKey()` is used for
simplicity but is vulnerable to man-in-the-middle attacks. After dialing the
server, a new session is created. `session.Run()` executes a command on the
remote server and waits for it to complete. The standard output of the command
is captured in a buffer and printed.

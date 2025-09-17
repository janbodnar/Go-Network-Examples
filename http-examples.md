# Go HTTP Networking Examples

This file contains 30 examples of networking with Go, with a focus on the
HTTP protocol. The examples are organized from basic to advanced.

---

## Simple GET request

This example shows how to make a simple HTTP GET request to a server.
It uses the `http.Get` convenience function.

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	resp, err := http.Get("https://httpbin.org/get")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))
}
```

The code makes a GET request to `httpbin.org/get`. The response body is read
and printed to the console. `http.Get` is a simple way to fetch a URL.
Error handling is important, as network requests can fail.

---

## GET request with query parameters

This example demonstrates how to add URL query parameters to a GET request.
It uses the `http.NewRequest` function to construct the request.

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	req, err := http.NewRequest("GET", "https://httpbin.org/get", nil)
	if err != nil {
		panic(err)
	}

	q := req.URL.Query()
	q.Add("key", "value")
	q.Add("another", "key")
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))
}
```

We create a request object and then add query parameters to its URL.
The parameters are encoded and attached to the raw query field.
This gives more control over the request than `http.Get`.

---

## POST request with form data

This example shows how to send a POST request with URL-encoded form data.
It uses the `url.Values` type and the `http.PostForm` function.

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

func main() {
	data := url.Values{}
	data.Set("key", "value")
	data.Set("name", "Jules")

	resp, err := http.PostForm("https://httpbin.org/post", data)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))
}
```

`http.PostForm` is a convenient way to send form data. It sets the
`Content-Type` header to `application/x-www-form-urlencoded` automatically.

---

## POST request with JSON body

This example demonstrates how to send a POST request with a JSON body.
It creates a JSON payload and sets the `Content-Type` header.

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	data := map[string]string{"name": "Jules"}
	jsonData, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	resp, err := http.Post("https://httpbin.org/post", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))
}
```

We first marshal a Go map into a JSON byte slice. Then we use `http.Post`
and provide the JSON data as the request body. The `Content-Type` header is
set to `application/json` to inform the server about the body format.

---

## Sending custom headers

This example shows how to add custom headers to an HTTP request.
It uses the `Header.Set` method on the request object.

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	req, err := http.NewRequest("GET", "https://httpbin.org/headers", nil)
	if err != nil {
		panic(err)
	}

	req.Header.Set("X-Custom-Header", "my-value")
	req.Header.Set("User-Agent", "Jules-Client/1.0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))
}
```

Custom headers are useful for sending metadata, such as API keys or
client information. We create a request and then add headers before sending.

---

## Reading response headers

This example demonstrates how to read headers from an HTTP response.
Response headers are stored in a map-like structure.

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	resp, err := http.Get("https://httpbin.org/response-headers?Content-Type=text/plain&Server=Jules-Server")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("Status:", resp.Status)
	fmt.Println("Content-Type:", resp.Header.Get("Content-Type"))
	fmt.Println("Server:", resp.Header.Get("Server"))
}
```

The response object contains a `Header` field, which is a map of strings.
We can access individual header values using the `Get` method.

---

## Handling cookies

This example shows how to send and receive cookies with an HTTP client.
It uses a `http.CookieJar` to manage cookies automatically.

```go
package main

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
)

func main() {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	client := &http.Client{Jar: jar}

	// This request will receive a cookie from httpbin
	_, err = client.Get("https://httpbin.org/cookies/set?my-cookie=123")
	if err != nil {
		panic(err)
	}

	// This request will send the cookie back to httpbin
	resp, err := client.Get("https://httpbin.org/cookies")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))
}
```

A `CookieJar` can be attached to an `http.Client` to store cookies from
responses and send them in subsequent requests to the same domain.

---

## Setting a custom timeout

This example demonstrates how to set a timeout for an HTTP request.
A timeout prevents a client from waiting indefinitely for a response.

```go
package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// This request will succeed
	_, err := client.Get("https://httpbin.org/get")
	if err != nil {
		fmt.Println("Request 1 failed:", err)
	} else {
		fmt.Println("Request 1 succeeded")
	}

	// This request will time out
	_, err = client.Get("https://httpbin.org/delay/10")
	if err != nil {
		fmt.Println("Request 2 failed:", err)
	} else {
		fmt.Println("Request 2 succeeded")
	}
}
```

Setting the `Timeout` field on the `http.Client` is the easiest way to
enforce a deadline for the entire request, including connection, reading
headers, and reading the body.

---

## Using a custom http.Transport

This example shows how to configure a custom `http.Transport` to control
connection-level settings like timeouts and keep-alives.

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

func main() {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://httpbin.org/get")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))
}
```

A custom `http.Transport` provides fine-grained control over the client's
network behavior. This is useful for optimizing performance and resilience.

---

## Handling redirects

This example demonstrates how the Go HTTP client handles redirects by default.
It also shows how to prevent redirects if needed.

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	client := &http.Client{}

	// This request will follow the redirect
	resp, err := client.Get("https://httpbin.org/redirect/1")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println("Redirect followed, final URL:", resp.Request.URL)

	// This client will not follow redirects
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err = client.Get("https://httpbin.org/redirect/1")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println("Redirect not followed, status code:", resp.StatusCode)
}
```

By default, the client follows up to 10 redirects. You can customize this
behavior by providing a `CheckRedirect` function to the client. Returning
`http.ErrUseLastResponse` stops the redirect chain.

---

## HTTPS with Self-Signed Certificate

This example shows how to make an HTTPS request to a server that uses a
self-signed certificate. By default, the client will reject it, so we must
configure a custom transport to handle it.

```go
package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	// Note: This is insecure and should only be used for testing.
	// In production, you should use a proper CA.
	// We will connect to a test server from badssl.com
	const url = "https://self-signed.badssl.com/"

	// Create a custom transport
	tr := &http.Transport{
		// We can't add the self-signed cert to a new CertPool, because we don't have it.
		// A common, but insecure, way to handle this is to skip verification.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("Response status:", resp.Status)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Body:", string(body[:50]), "...")
}
```

Connecting to a server with a self-signed certificate without proper
configuration will result in an `x509: certificate signed by unknown authority`
error. The code above shows how to bypass this for testing purposes by setting
`InsecureSkipVerify` to true. This is not recommended for production use.

---

## Basic HTTP Server

This example demonstrates how to create a basic HTTP server that listens on
port 8080 and responds with "Hello, World!".

```go
package main

import (
	"fmt"
	"net/http"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World!")
}

func main() {
	http.HandleFunc("/", helloHandler)
	fmt.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
```

To run this server, save it as `server.go` and execute `go run server.go`.
You can then test it by navigating to `http://localhost:8080` in your browser
or by using `curl http://localhost:8080`.

---

## Server with Routing

This example shows how to handle different URL paths with different handlers.
This is the basis of routing in web applications.

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Welcome to the home page!")
	})
	http.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "This is the about page.")
	})
	http.HandleFunc("/contact", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Contact us here.")
	})

	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", nil)
}
```

The `http.HandleFunc` function registers a handler for a given path. The
default serve mux dispatches requests to the appropriate handler based on the
URL path. More complex routing can be achieved with third-party libraries.

---

## Server Handling Different Methods

This example demonstrates how to handle different HTTP methods (GET, POST) for
the same URL path.

```go
package main

import (
	"fmt"
	"net/http"
)

func formHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Serve the form
		fmt.Fprintf(w, `
			<form method="POST">
				<label for="name">Name:</label>
				<input type="text" id="name" name="name">
				<button type="submit">Submit</button>
			</form>
		`)
	case "POST":
		// Handle the form submission
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		name := r.FormValue("name")
		fmt.Fprintf(w, "Hello, %s!", name)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	http.HandleFunc("/form", formHandler)
	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", nil)
}
```

Inside the handler, we use a `switch` statement on `r.Method` to execute
different logic for GET and POST requests. This allows a single endpoint to
serve a form and process its submission.

---

## Server Reading JSON Body

This example shows how to create a server that reads and parses a JSON
request body.

```go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var u User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "Received user: %+v", u)
}

func main() {
	http.HandleFunc("/user", userHandler)
	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", nil)
}
```

We use `json.NewDecoder` to decode the JSON from the request body directly
into a Go struct. This is an efficient way to handle JSON input. You can
test this with `curl -X POST -d '{"name":"Jules","email":"jules@example.com"}' http://localhost:8080/user`.

---

## Server Writing JSON Response

This example demonstrates how to write a JSON response from a server.

```go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type ResponseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	data := ResponseData{Status: "ok", Message: "Server is running"}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/status", statusHandler)
	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", nil)
}
```

We set the `Content-Type` header to `application/json` to inform the client
that we are sending JSON. `json.NewEncoder` writes the encoded JSON directly
to the `http.ResponseWriter`, which is very efficient.

---

## Server Serving Static Files

This example shows how to serve static files like HTML, CSS, and JavaScript.
It uses the `http.FileServer` handler.

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	// Create a file server handler to serve files from the "static" directory
	fs := http.FileServer(http.Dir("./static"))

	// Handle all requests with the file server
	http.Handle("/", fs)

	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", nil)
}
```

To use this, create a directory named `static` in the same folder as your
Go program. Place some files in it, like `index.html`. When you run the
server and navigate to `http://localhost:8080`, it will serve `index.html`.

---

## Server with Middleware for Logging

This example demonstrates how to use middleware to log incoming requests.
Middleware is a function that wraps a handler to add functionality.

```go
package main

import (
	"fmt"
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
	fmt.Fprintf(w, "Hello, World!")
}

func main() {
	http.Handle("/", loggingMiddleware(http.HandlerFunc(helloHandler)))
	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", nil)
}
```

The `loggingMiddleware` function takes a handler and returns a new handler.
The new handler logs the request, calls the original handler, and then logs
the completion. This is a powerful pattern for adding cross-cutting concerns.

---

## Server with Middleware for Authentication

This example shows how to use middleware for simple token-based authentication.
It checks for a specific `Authorization` header.

```go
package main

import (
	"fmt"
	"net/http"
)

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer my-secret-token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "This is a protected area.")
}

func main() {
	http.Handle("/protected", authMiddleware(http.HandlerFunc(protectedHandler)))
	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", nil)
}
```

The `authMiddleware` checks for a valid token. If the token is missing or
invalid, it returns an `Unauthorized` error and stops processing. Otherwise,
it calls the next handler in the chain. Test with `curl -H "Authorization: Bearer my-secret-token" http://localhost:8080/protected`.

---

## File Upload with multipart/form-data

This example shows how a client can upload a file to a server using a
multipart POST request. We'll use `httpbin.org/post` to receive the file.

```go
package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
)

func main() {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	// Add a file
	f, err := os.Open("file.txt") // Create a dummy file.txt
	if err != nil {
		// Create a dummy file for the example
		ioutil.WriteFile("file.txt", []byte("hello world"), 0644)
		f, err = os.Open("file.txt")
		if err != nil {
			panic(err)
		}
	}
	defer f.Close()
	fw, err := w.CreateFormFile("file", "file.txt")
	if err != nil {
		panic(err)
	}
	if _, err = io.Copy(fw, f); err != nil {
		panic(err)
	}

	// Add a field
	if fw, err = w.CreateFormField("key"); err != nil {
		panic(err)
	}
	if _, err = fw.Write([]byte("value")); err != nil {
		panic(err)
	}

	w.Close()

	req, err := http.NewRequest("POST", "https://httpbin.org/post", &b)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}
```

This code constructs a `multipart/form-data` body by creating a file part
and a form field part. The `Content-Type` header is set with the boundary
generated by the `multipart.Writer`. This is how browsers upload files.

---

## File Download

This example shows how to download a file from a URL and save it to disk.
It's important to handle file creation and writing errors.

```go
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	resp, err := http.Get("https://httpbin.org/image/jpeg")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create("image.jpg")
	if err != nil {
		panic(err)
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println("Image downloaded successfully.")
}
```

We make a GET request to the URL of the file we want to download. Then we
create a local file and use `io.Copy` to write the response body into it.
This is an efficient way to handle large files as it streams the data.

---

## Using Context for Cancellation

This example demonstrates how to use a `context` to cancel an in-flight
HTTP request. This is crucial for managing long-running requests.

```go
package main

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func main() {
	// Create a context that will be canceled after 3 seconds
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://httpbin.org/delay/5", nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("Sending request with 3s timeout to a 5s endpoint...")
	_, err = http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Request failed as expected:", err)
	} else {
		fmt.Println("Request succeeded unexpectedly")
	}
}
```

We create a request with a context that has a timeout. If the request takes
longer than the timeout, the context is canceled, and the client will abort
the request, returning an error.

---

## Client with Connection Pool

The default Go HTTP client uses a connection pool. This example shows how to
customize the transport to configure the pool's behavior.

```go
package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
	}
	client := &http.Client{Transport: transport}

	// Make a few requests to see the pooling in action
	for i := 0; i < 15; i++ {
		resp, err := client.Get("https://httpbin.org/get")
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		resp.Body.Close()
		fmt.Println("Request", i+1, "done.")
	}
}
```

By customizing the `http.Transport`, you can control how many idle connections
are kept in the pool and for how long. This is important for managing resources
in high-performance clients.

---

## Streaming Request Body

This example shows how to stream a request body, which is useful when sending
large amounts of data without buffering it all in memory.

```go
package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	r, w := io.Pipe()

	go func() {
		defer w.Close()
		for i := 0; i < 5; i++ {
			fmt.Fprintf(w, "Line %d\n", i+1)
			time.Sleep(1 * time.Second)
		}
	}()

	req, err := http.NewRequest("POST", "https://httpbin.org/post", r)
	if err != nil {
		panic(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("Response status:", resp.Status)
}
```

We use an `io.Pipe` to connect a writer to a reader. The request body is the
pipe's reader. We can then write to the pipe's writer in a separate goroutine,
and the data will be streamed as the request body.

---

## Streaming Response Body

This server-side example shows how to stream a response body. This is useful
for sending large or real-time data to a client.

```go
package main

import (
	"fmt"
	"net/http"
	"time"
)

func streamHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	for i := 0; i < 10; i++ {
		fmt.Fprintf(w, "data: Chunk %d\n\n", i+1)
		flusher.Flush() // Send the chunk to the client
		time.Sleep(1 * time.Second)
	}
}

func main() {
	http.HandleFunc("/stream", streamHandler)
	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", nil)
}
```

The key to streaming on the server is the `http.Flusher` interface. By calling
`Flush()`, we force the server to send any buffered data to the client. This
is the foundation of Server-Sent Events (SSE).

---

## HTTP/2 Client

Go's HTTP client supports HTTP/2 automatically when making HTTPS requests.
This example shows how to confirm that HTTP/2 is being used.

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	resp, err := http.Get("https://http2.pro/api/v1")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("Protocol:", resp.Proto) // Should be HTTP/2.0
}
```

When connecting to an HTTPS server that supports HTTP/2, the Go client will
automatically upgrade the connection. You can inspect the `resp.Proto` field
to see which protocol version was used.

---

## HTTP/2 Server

Go's `http.Server` supports HTTP/2 out of the box. You just need to provide
it with a TLS configuration.

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, you are using protocol %s", r.Proto)
	})

	fmt.Println("Starting server on :8443")
	// To run this, you need a cert and key file.
	// You can generate them with:
	// go run /usr/local/go/src/crypto/tls/generate_cert.go --host localhost
	err := http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)
	if err != nil {
		panic(err)
	}
}
```

As long as you use `ListenAndServeTLS`, the server will enable HTTP/2 support.
Clients that support HTTP/2 will automatically use it. You can test this with
`curl -k --http2 https://localhost:8443`.

---

## Basic HTTP Proxy

This example implements a basic HTTP proxy server. It takes incoming requests
and forwards them to their destination.

```go
package main

import (
    "io"
    "net/http"
    "log"
)

func proxyHandler(w http.ResponseWriter, r *http.Request) {
    destReq, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    destReq.Header = r.Header

    resp, err := http.DefaultTransport.RoundTrip(destReq)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    for k, vv := range resp.Header {
        for _, v := range vv {
            w.Header().Add(k, v)
        }
    }
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}

func main() {
    log.Println("Starting proxy server on :8080")
    if err := http.ListenAndServe(":8080", http.HandlerFunc(proxyHandler)); err != nil {
        log.Fatal(err)
    }
}
```

This proxy is a simple handler that creates a new request based on the incoming
one and sends it using the default transport. It then copies the response back
to the original client. Test it with `curl -x http://localhost:8080 http://example.com`.

---

## Reverse Proxy

A reverse proxy is a server that sits in front of other servers and forwards
client requests to them. The `httputil` package makes this easy.

```go
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	target, err := url.Parse("https://httpbin.org")
	if err != nil {
		log.Fatal(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	http.Handle("/", proxy)

	log.Println("Starting reverse proxy on :8080")
	http.ListenAndServe(":8080", nil)
}
```

This reverse proxy forwards all incoming requests to `httpbin.org`. If you run
this and go to `http://localhost:8080/get`, you will see the response from
`https://httpbin.org/get`. It's a powerful tool for load balancing and routing.

---

## WebSockets over HTTP

This example shows how to create a WebSocket echo server. It requires the
`gorilla/websocket` package, which is a popular choice for WebSockets in Go.

```go
package main

import (
	"log"
	"net/http"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{} // use default options

func echo(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			break
		}
		log.Printf("recv: %s", message)
		err = c.WriteMessage(mt, message)
		if err != nil {
			log.Println("write:", err)
			break
		}
	}
}

func main() {
	http.HandleFunc("/echo", echo)
	log.Println("Starting websocket server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

To run this, you first need to fetch the package: `go get github.com/gorilla/websocket`.
The server upgrades an HTTP connection to a WebSocket connection and then enters
a loop to read messages and echo them back to the client.

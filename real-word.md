# Web crawler with concurrency

This example shows a simple concurrent web crawler. It starts from a seed  
URL, fetches the page, extracts all links, and then recursively crawls  
the discovered links in parallel using goroutines.  

```go
package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// Visited tracks visited URLs to avoid cycles and redundant fetches.
type Visited struct {
	mu      sync.Mutex
	visited map[string]bool
}

// Visit marks a URL as visited. It returns true if the URL was already visited.
func (v *Visited) Visit(url string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.visited[url] {
		return true
	}
	v.visited[url] = true
	return false
}

// fetchAndParse fetches and parses the HTML content of a URL.
func fetchAndParse(url string) (*html.Node, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get URL %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get URL %s: status code %d", url, 
			resp.StatusCode)
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML from %s: %w", url, err)
	}
	return doc, nil
}

// extractLinks finds all href attributes in anchor tags.
func extractLinks(n *html.Node) []string {
	var links []string
	if n.Type == html.ElementNode && n.Data == "a" {
		for _, a := range n.Attr {
			if a.Key == "href" {
				links = append(links, a.Val)
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		links = append(links, extractLinks(c)...)
	}
	return links
}

// crawl is the main worker function for the crawler.
func crawl(url string, fetched chan<- string, visited *Visited) {
	if visited.Visit(url) {
		return
	}
	fmt.Printf("Crawling: %s\n", url)

	doc, err := fetchAndParse(url)
	if err != nil {
		fmt.Printf("Error crawling %s: %v\n", url, err)
		return
	}

	links := extractLinks(doc)
	for _, link := range links {
		// Basic URL resolution
		base, err := http.ProxyURL(nil)(nil)
		if err != nil {
			fmt.Printf("Error resolving base URL: %v\n", err)
			continue
		}
		absURL, err := base.Parse(link)
		if err != nil {
			fmt.Printf("Error parsing link %s: %v\n", link, err)
			continue
		}
		go crawl(absURL.String(), fetched, visited)
	}
	fetched <- url
}

func main() {
	startURL := "http://example.com"
	fetched := make(chan string)
	visited := &Visited{
		visited: make(map[string]bool),
	}

	go crawl(startURL, fetched, visited)

	// Wait for fetches to complete, with a timeout
	timeout := time.After(10 * time.Second)
	for i := 0; i < 1; { // We only expect one URL in this simple case
		select {
		case url := <-fetched:
			fmt.Printf("Finished crawling: %s\n", url)
			i++
		case <-timeout:
			fmt.Println("Timed out waiting for crawl to finish.")
			return
		}
	}
}
```

This code defines a `crawl` function that fetches and parses a URL,  
extracts links, and then spawns new goroutines to crawl those links.  
A `Visited` struct with a mutex is used to safely track visited URLs  
across multiple goroutines, preventing duplicate work and infinite loops.  
The main function initializes the process and uses a channel to wait for  
the initial crawl to complete, with a timeout to prevent it from running  
indefinitely. This example demonstrates a fundamental pattern for  
concurrent network clients in Go.  

---

# REST API client with pagination

This example demonstrates how to build a REST API client that handles  
paginated responses. It uses the GitHub API to fetch all stargazers for a  
repository, following the `Link` header to navigate through pages.  

```go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

// Stargazer defines the structure for a GitHub stargazer.
type Stargazer struct {
	Login string `json:"login"`
	ID    int    `json:"id"`
}

// findNextPage extracts the next page URL from the Link header.
func findNextPage(resp *http.Response) string {
	linkHeader := resp.Header.Get("Link")
	if linkHeader == "" {
		return ""
	}

	// The Link header contains URLs in the format:
	// <https://api.github.com/repositories/1300192/stargazers?page=2>; 
	// rel="next", ...
	re := regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)
	matches := re.FindStringSubmatch(linkHeader)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// getStargazers fetches all stargazers for a given repository.
func getStargazers(repo string) ([]Stargazer, error) {
	var allStargazers []Stargazer
	url := fmt.Sprintf("https://api.github.com/repos/%s/stargazers", repo)

	for url != "" {
		fmt.Printf("Fetching URL: %s\n", url)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		// GitHub API requires a User-Agent header.
		req.Header.Set("User-Agent", "Go-REST-Client")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to get stargazers: %s", resp.Status)
		}

		var stargazers []Stargazer
		if err := json.NewDecoder(resp.Body).Decode(&stargazers); err != nil {
			return nil, err
		}
		allStargazers = append(allStargazers, stargazers...)

		url = findNextPage(resp)
	}

	return allStargazers, nil
}

func main() {
	// A popular repository to test with.
	repo := "golang/go"
	stargazers, err := getStargazers(repo)
	if err != nil {
		fmt.Printf("Error fetching stargazers for %s: %v\n", repo, err)
		return
	}

	fmt.Printf("Total stargazers for %s: %d\n", repo, len(stargazers))
	// Print the first 10 stargazers for brevity.
	for i := 0; i < 10 && i < len(stargazers); i++ {
		fmt.Printf("- %s\n", stargazers[i].Login)
	}
}
```

This code fetches a list of stargazers from the GitHub API. The  
`getStargazers` function repeatedly makes HTTP GET requests, and after each  
request, it calls `findNextPage` to parse the `Link` header for the URL of  
the next page of results. The loop continues until there are no more "next"  
pages. This is a common pattern for consuming paginated APIs and shows how  
to handle headers and JSON decoding in Go.  

---

# OAuth2 token fetcher

This example demonstrates how to fetch an OAuth2 access token using the  
client credentials flow. This flow is typically used for machine-to-machine  
authentication. The `golang.org/x/oauth2` package simplifies this process.  

```go
package main

import (
	"context"
	"fmt"
	"log"

	"golang.org/x/oauth2/clientcredentials"
)

func main() {
	// This is a mock configuration. In a real application, you would get these
	// from your OAuth2 provider.
	config := clientcredentials.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		TokenURL:     "https://example.com/oauth/token",
		// Scopes are optional and depend on the provider.
		Scopes: []string{"api:read"},
	}

	// The context is used to manage the request's lifecycle.
	ctx := context.Background()

	// Fetch the token.
	token, err := config.Token(ctx)
	if err != nil {
		log.Fatalf("Failed to get token: %v", err)
	}

	fmt.Printf("Access Token: %s\n", token.AccessToken)
	fmt.Printf("Token Type: %s\n", token.TokenType)
	if !token.Expiry.IsZero() {
		fmt.Printf("Expires At: %s\n", token.Expiry)
	}
}
```

This code sets up an OAuth2 configuration with a client ID, secret, and  
token URL. It then uses the `config.Token` method to request an access  
token from the provider. The `context.Background()` provides a default  
context for the request. The resulting token, which includes the access  
token, type, and expiration, is then printed. This example can be easily  
adapted to work with any OAuth2 provider that supports the client  
credentials grant.  

---

# Git client over TCP

This example demonstrates a basic Git client that connects to a Git server  
over TCP (port 9418) and fetches the list of references (branches and  
tags). It implements a small part of the Git wire protocol, showing how to  
work with a custom binary protocol.  

```go
package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

// pktLineEncode creates a Git pkt-line formatted string.
func pktLineEncode(s string) string {
	return fmt.Sprintf("%04x%s", len(s)+4, s)
}

// pktLineFlush is the special flush packet.
const pktLineFlush = "0000"

func main() {
	// The host and repository to connect to.
	host := "github.com:9418"
	repo := "github.com/git/git" // The repository path on the server.

	// Connect to the Git server.
	conn, err := net.Dial("tcp", host)
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v", host, err)
	}
	defer conn.Close()
	fmt.Printf("Connected to %s\n", host)

	// Construct the request to fetch the refs.
	// The format is "git-upload-pack /path/to/repo.git\0host=hostname\0"
	request := fmt.Sprintf("git-upload-pack /%s.git\x00host=%s\x00", repo, 
		"github.com")

	// Send the request using pkt-line encoding.
	_, err = conn.Write([]byte(pktLineEncode(request)))
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	fmt.Println("Sent request to fetch refs.")

	// Read the response from the server.
	reader := bufio.NewReader(conn)
	for {
		// Read the 4-byte length prefix.
		lengthHex := make([]byte, 4)
		if _, err := io.ReadFull(reader, lengthHex); err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("Failed to read length prefix: %v", err)
		}

		lineLength := 0
		fmt.Sscanf(string(lengthHex), "%x", &lineLength)

		if lineLength == 0 {
			// This is a flush packet, indicating the end of the ref list.
			break
		}

		// Read the rest of the line.
		line := make([]byte, lineLength-4)
		if _, err := io.ReadFull(reader, line); err != nil {
			log.Fatalf("Failed to read line: %v", err)
		}

		// The first line contains capabilities.
		if strings.Contains(string(line), "capabilities") {
			fmt.Printf("Server capabilities: %s\n", line)
			continue
		}

		// Subsequent lines are the refs.
		parts := strings.SplitN(string(line), " ", 2)
		if len(parts) == 2 {
			sha, ref := parts[0], strings.TrimSpace(parts[1])
			fmt.Printf("Ref: %s, SHA: %s\n", ref, sha)
		}
	}

	fmt.Println("Finished fetching refs.")
}
```

This code connects to a Git server and sends a request to "upload-pack"  
(which is used for fetching). The request is formatted using the `pkt-line`  
protocol, which prefixes each line with its length in hexadecimal. The  
server responds with a list of references, also in `pkt-line` format. The  
client reads the response line by line, parsing the length prefix to  
determine how much to read. This example provides insight into how low-level  
network protocols can be implemented in Go.  

---

# SSH client (basic handshake)

This example demonstrates how to create an SSH client that performs a basic  
handshake with a server. It uses the `golang.org/x/crypto/ssh` package to  
handle the complexities of the SSH protocol.  

```go
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
```

This code sets up an SSH client configuration with a username and password,  
and then connects to an SSH server. The `ssh.NewClientConn` function  
handles the handshake process, including version exchange, key exchange,  
and authentication. For simplicity, this example uses  
`ssh.InsecureIgnoreHostKey` to bypass host key verification, which is not  
recommended for production use. The server's version string is printed upon  
a successful connection.  

---

# VPN tunnel over TCP

This example demonstrates a simple VPN tunnel over TCP. It consists of a
client and a server that create a virtual network interface (TUN) and
forward packets between them over a TCP connection. This creates a basic
point-to-point VPN.

```go
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
```

This code can be run in two modes: `server` and `client`. The server
listens for a TCP connection, while the client connects to the server. Both
create a TUN interface and assign it an IP address. Once the connection is
established, `io.Copy` is used to forward data between the TUN interface
and the TCP socket. This effectively creates a tunnel. Note that this
example requires root privileges to create and configure the network
interface and depends on the `ip` command-line tool.

---

# WebRTC signaling client

This example demonstrates a WebRTC signaling client that connects to a
WebSocket server to exchange session descriptions with a peer. It uses the
`pion/webrtc` library for WebRTC and `gorilla/websocket` for the signaling
channel.

```go
package main

import (
	"encoding/json"
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v3"
)

// Message defines the structure for signaling messages.
type Message struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
}

func main() {
	// The WebSocket server URL for signaling.
	// This is a public server for testing purposes.
	u := url.URL{Scheme: "wss", Host: "pion-webrtc.herokuapp.com", Path: "/"}
	log.Printf("Connecting to %s", u.String())

	// Connect to the signaling server.
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer c.Close()

	// Create a new WebRTC peer connection.
	peerConnection, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		log.Fatalf("Failed to create peer connection: %v", err)
	}
	defer peerConnection.Close()

	// Create a data channel.
	dataChannel, err := peerConnection.CreateDataChannel("data", nil)
	if err != nil {
		log.Fatalf("Failed to create data channel: %v", err)
	}

	dataChannel.OnOpen(func() {
		log.Printf("Data channel '%s'-'%d' open. Random messages will be sent "+
			"to any connected DataChannels every 5 seconds", 
			dataChannel.Label(), dataChannel.ID())
		for range time.NewTicker(5 * time.Second).C {
			message := "Hello from client!"
			log.Printf("Sending message: %s", message)
			if err := dataChannel.SendText(message); err != nil {
				log.Printf("Failed to send message: %v", err)
			}
		}
	})

	dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		log.Printf("Message from data channel '%s': '%s'", 
			dataChannel.Label(), string(msg.Data))
	})

	// Create an offer.
	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		log.Fatalf("Failed to create offer: %v", err)
	}
	if err := peerConnection.SetLocalDescription(offer); err != nil {
		log.Fatalf("Failed to set local description: %v", err)
	}

	// Send the offer to the signaling server.
	offerData, err := json.Marshal(offer)
	if err != nil {
		log.Fatalf("Failed to marshal offer: %v", err)
	}
	if err := c.WriteJSON(Message{Event: "offer", 
		Data: string(offerData)}); err != nil {
		log.Fatalf("Failed to write offer: %v", err)
	}

	// Handle incoming messages from the signaling server.
	go func() {
		for {
			var msg Message
			if err := c.ReadJSON(&msg); err != nil {
				log.Printf("Failed to read message: %v", err)
				return
			}

			if msg.Event == "answer" {
				var answer webrtc.SessionDescription
				if err := json.Unmarshal([]byte(msg.Data.(string)), &answer); err != nil {
					log.Printf("Failed to unmarshal answer: %v", err)
					continue
				}
				if err := peerConnection.SetRemoteDescription(answer); err != nil {
					log.Printf("Failed to set remote description: %v", err)
				}
			}
		}
	}()

	// Wait for Ctrl+C to exit.
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	<-interrupt
	log.Println("Exiting...")
}
```

This code connects to a WebSocket server, creates a WebRTC peer connection,
and then creates an offer. The offer is sent to the signaling server, which
is expected to forward it to another peer. The client then waits for an
answer from the other peer. Once the answer is received, the connection is
established, and a data channel is opened for sending and receiving
messages. This example illustrates the fundamental concepts of WebRTC
signaling.

---

# QUIC client (basic handshake)

This example demonstrates a basic QUIC client that connects to a server and
performs a handshake. It uses the `lucas-clemente/quic-go` library, a
popular implementation of the QUIC protocol in Go.

```go
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
		InsecureSkipVerify: true, // In a real application, you should 
		                         // verify the server's certificate.
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
```

This code connects to a QUIC server using `quic.DialAddr`. It configures a
`tls.Config` because QUIC is always encrypted with TLS 1.3. The `NextProtos`
field is used for Application-Layer Protocol Negotiation (ALPN), which is
how the client and server agree on the application protocol to use over
QUIC (in this case, "h3" for HTTP/3). The example performs a handshake and
opens a stream, demonstrating the basic setup for a QUIC connection.

---

# DNS-over-HTTPS client

This example demonstrates a DNS-over-HTTPS (DoH) client. It uses the
`miekg/dns` library to construct and parse DNS messages, and the standard
`net/http` package to send the query over an encrypted HTTPS connection.

```go
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/miekg/dns"
)

func main() {
	// The domain to query.
	domain := "example.com."
	// The DoH server to use.
	dohServer := "https://cloudflare-dns.com/dns-query"

	// Create a new DNS query message.
	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeA)
	msg.RecursionDesired = true

	// Pack the message into a byte slice.
	packedMsg, err := msg.Pack()
	if err != nil {
		log.Fatalf("Failed to pack message: %v", err)
	}

	// Create the HTTP request.
	req, err := http.NewRequest("POST", dohServer, bytes.NewReader(packedMsg))
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// Send the request.
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Request failed with status: %s", resp.Status)
	}

	// Read the response body.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	// Unpack the response into a DNS message.
	var respMsg dns.Msg
	if err := respMsg.Unpack(body); err != nil {
		log.Fatalf("Failed to unpack response: %v", err)
	}

	// Print the answer.
	fmt.Printf("DNS query for %s:\n", domain)
	for _, ans := range respMsg.Answer {
		if a, ok := ans.(*dns.A); ok {
			fmt.Printf("- %s\n", a.A)
		}
	}
}
```

This code first creates a DNS query message for an A record. The message is
then packed into a binary format. This binary data is sent as the body of an
HTTP POST request to a DoH server. The server's response, which is also a
binary DNS message, is unpacked and the resulting IP addresses are printed.
This example shows how to combine DNS and HTTP protocols to implement DoH.

---

# TLS termination proxy

This example demonstrates a TLS termination proxy. The proxy listens for
encrypted TLS (HTTPS) connections, decrypts them, and forwards the plaintext
traffic to a backend HTTP server. It generates a self-signed certificate
on the fly for simplicity.

```go
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

		KeyUsage:              x509.KeyUsageKeyEncipherment | 
		                      x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, 
		&template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", 
		Bytes: derBytes})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", 
		Bytes: x509.MarshalPKCS1PrivateKey(priv)})

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
```

This code sets up a TLS listener on `localhost:8443`. When a client connects,
the proxy accepts the connection, decrypts the TLS traffic, and then opens a
new, unencrypted TCP connection to the backend server at `localhost:8080`.
The `io.Copy` function is used to shuttle data between the client and the
backend. This is a common pattern for securing services that do not have
built-in TLS support.

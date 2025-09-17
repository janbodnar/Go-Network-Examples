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
	request := fmt.Sprintf("git-upload-pack /%s.git\x00host=%s\x00", repo, "github.com")

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

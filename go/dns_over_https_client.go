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

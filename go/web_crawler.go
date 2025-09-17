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
		return nil, fmt.Errorf("failed to get URL %s: status code %d", url, resp.StatusCode)
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

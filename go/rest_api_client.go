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
	// <https://api.github.com/repositories/1300192/stargazers?page=2>; rel="next", ...
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

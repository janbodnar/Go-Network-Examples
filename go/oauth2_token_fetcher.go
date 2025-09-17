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

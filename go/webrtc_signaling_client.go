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
		log.Printf("Data channel '%s'-'%d' open. Random messages will be sent to any connected DataChannels every 5 seconds", dataChannel.Label(), dataChannel.ID())
		for range time.NewTicker(5 * time.Second).C {
			message := "Hello from client!"
			log.Printf("Sending message: %s", message)
			if err := dataChannel.SendText(message); err != nil {
				log.Printf("Failed to send message: %v", err)
			}
		}
	})

	dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		log.Printf("Message from data channel '%s': '%s'", dataChannel.Label(), string(msg.Data))
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
	if err := c.WriteJSON(Message{Event: "offer", Data: string(offerData)}); err != nil {
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

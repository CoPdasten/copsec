package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// WSMessage represents a typed real-time WebSocket packet.
type WSMessage struct {
	Type      string      `json:"type"` // "event", "stats", "ban_change", "honeypot_hit", "mitre_stats"
	Timestamp int64       `json:"timestamp"`
	Payload   interface{} `json:"payload"`
}

// WSClient represents a connected frontend dashboard session.
type WSClient struct {
	hub      *WSHub
	ws       *websocket.Conn
	sendChan chan []byte
	closed   bool
	mu       sync.Mutex
}

// WSHub coordinates zero-backpressure broadcasting to active Web SOC clients.
type WSHub struct {
	mu         sync.RWMutex
	clients    map[*WSClient]bool
	broadcast  chan []byte
	register   chan *WSClient
	unregister chan *WSClient
	stopChan   chan struct{}
}

// NewWSHub initializes the non-blocking WebSocket broadcast hub.
func NewWSHub() *WSHub {
	hub := &WSHub{
		clients:    make(map[*WSClient]bool),
		broadcast:  make(chan []byte, 1024),
		register:   make(chan *WSClient, 64),
		unregister: make(chan *WSClient, 64),
		stopChan:   make(chan struct{}),
	}
	go hub.run()
	return hub
}

func (h *WSHub) run() {
	for {
		select {
		case <-h.stopChan:
			h.mu.Lock()
			for client := range h.clients {
				client.Close()
			}
			h.clients = make(map[*WSClient]bool)
			h.mu.Unlock()
			return

		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.Close()
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				client.SendNonBlocking(message)
			}
			h.mu.RUnlock()
		}
	}
}

// SendNonBlocking sends data to a client or drops if buffer is full (Zero Backpressure).
func (c *WSClient) SendNonBlocking(msg []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	select {
	case c.sendChan <- msg:
	default:
		// Queue full: drop message to ensure zero backpressure on main event pipeline
	}
}

// Close disconnects client and flushes buffer.
func (c *WSClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.closed {
		c.closed = true
		close(c.sendChan)
		_ = c.ws.Close()
	}
}

func (c *WSClient) writePump() {
	defer func() {
		c.hub.unregister <- c
	}()

	for msg := range c.sendChan {
		_ = c.ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
		err := websocket.Message.Send(c.ws, string(msg))
		if err != nil {
			return
		}
	}
}

func (c *WSClient) readPump() {
	defer func() {
		c.hub.unregister <- c
	}()

	for {
		var msg string
		err := websocket.Message.Receive(c.ws, &msg)
		if err != nil {
			if err != io.EOF {
				// Client disconnected
			}
			break
		}
		// Incoming ping/message from client
	}
}

// Broadcast sends a typed message to all connected SOC sessions.
func (h *WSHub) Broadcast(msgType string, payload interface{}) {
	msg := WSMessage{
		Type:      msgType,
		Timestamp: time.Now().UnixMilli(),
		Payload:   payload,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	select {
	case h.broadcast <- data:
	default:
		// Drop from hub broadcast channel if saturated
	}
}

// isAllowedOrigin validates incoming WebSocket Origin against local addresses and host.
func isAllowedOrigin(config *websocket.Config, req *http.Request) bool {
	originHeader := req.Header.Get("Origin")
	if originHeader == "" {
		// Non-browser client or same-origin request without Origin header
		return true
	}

	parsed, err := url.Parse(originHeader)
	if err != nil {
		return false
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return true
	}

	// Match host header of the incoming request
	reqHost := req.Host
	if strings.Contains(reqHost, ":") {
		reqHost = strings.Split(reqHost, ":")[0]
	}
	if strings.EqualFold(hostname, reqHost) {
		return true
	}

	return false
}

// Handler returns an HTTP handler for WebSocket upgrades with origin validation.
func (h *WSHub) Handler() http.Handler {
	wsServer := websocket.Server{
		Handshake: func(config *websocket.Config, req *http.Request) error {
			if !isAllowedOrigin(config, req) {
				return websocket.ErrBadWebSocketOrigin
			}
			return nil
		},
		Handler: websocket.Handler(func(ws *websocket.Conn) {
			client := &WSClient{
				hub:      h,
				ws:       ws,
				sendChan: make(chan []byte, 256),
			}
			h.register <- client

			go client.writePump()
			client.readPump()
		}),
	}
	return wsServer
}

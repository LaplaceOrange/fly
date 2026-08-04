package realtime

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type Hub struct {
	mu      sync.Mutex
	clients map[*client]struct{}
	closed  bool
}

type client struct {
	connection *websocket.Conn
	send       chan []byte
}

type Event struct {
	Type     string `json:"type"`
	Revision int64  `json:"revision"`
	Flight   any    `json:"flight,omitempty"`
}

func NewHub() *Hub { return &Hub{clients: make(map[*client]struct{})} }

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request, revision int64) {
	connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns:  []string{r.Host},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	connection.SetReadLimit(1024)
	ctx := connection.CloseRead(r.Context())
	subscriber := &client{connection: connection, send: make(chan []byte, 16)}
	if !h.register(subscriber) {
		_ = connection.Close(websocket.StatusGoingAway, "server shutting down")
		return
	}
	defer h.unregister(subscriber)
	defer connection.Close(websocket.StatusNormalClosure, "bye")

	connected, _ := json.Marshal(Event{Type: "connected", Revision: revision})
	select {
	case subscriber.send <- connected:
	default:
	}

	for {
		select {
		case <-ctx.Done():
			return
		case message := <-subscriber.send:
			writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := connection.Write(writeCtx, websocket.MessageText, message)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

func (h *Hub) Broadcast(event Event) {
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}
	var dropped []*client
	h.mu.Lock()
	for subscriber := range h.clients {
		select {
		case subscriber.send <- payload:
		default:
			delete(h.clients, subscriber)
			dropped = append(dropped, subscriber)
		}
	}
	h.mu.Unlock()
	for _, subscriber := range dropped {
		subscriber.connection.CloseNow()
	}
}

func (h *Hub) Close() {
	h.mu.Lock()
	h.closed = true
	clients := make([]*client, 0, len(h.clients))
	for subscriber := range h.clients {
		clients = append(clients, subscriber)
		delete(h.clients, subscriber)
	}
	h.mu.Unlock()
	for _, subscriber := range clients {
		_ = subscriber.connection.Close(websocket.StatusGoingAway, "server shutting down")
	}
}

func (h *Hub) register(subscriber *client) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	h.clients[subscriber] = struct{}{}
	return true
}

func (h *Hub) unregister(subscriber *client) {
	h.mu.Lock()
	delete(h.clients, subscriber)
	h.mu.Unlock()
}

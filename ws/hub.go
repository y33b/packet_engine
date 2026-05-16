package ws

import (
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type WSMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type Hub struct {
	Clients   map[*websocket.Conn]bool
	Broadcast chan WSMessage
	Upgrader  websocket.Upgrader
	mu        sync.Mutex
}

func NewHub() *Hub {
	return &Hub{
		Clients:   make(map[*websocket.Conn]bool),
		Broadcast: make(chan WSMessage, 100),
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (h *Hub) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := h.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	h.mu.Lock()
	h.Clients[conn] = true
	h.mu.Unlock()

	go h.readPump(conn)
}

func (h *Hub) readPump(conn *websocket.Conn) {
	defer func() {
		h.mu.Lock()
		delete(h.Clients, conn)
		h.mu.Unlock()
		conn.Close()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (h *Hub) Run() {
	for msg := range h.Broadcast {

		h.mu.Lock()

		for client := range h.Clients {
			err := client.WriteJSON(msg)
			if err != nil {
				client.Close()
				delete(h.Clients, client)
			}
		}

		h.mu.Unlock()
	}
}

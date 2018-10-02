// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "fmt"

type message struct {
	body []byte
	room string
}

type subscription struct {
	conn  *Client
	room  string
	rooms []string
	user  ChatUser
	exp   int64
}

// Hub maintains the set of active clients and broadcasts messages to the
// clients.
type Hub struct {
	// Registered clients.
	rooms map[string]map[*Client]bool

	// Inbound messages from the clients.
	broadcast chan message

	// Register requests from the clients.
	register chan subscription

	// Unregister requests from clients.
	unregister chan subscription

	unregisterOne chan subscription
}

func newHub() *Hub {
	return &Hub{
		broadcast:     make(chan message),
		register:      make(chan subscription),
		unregister:    make(chan subscription),
		unregisterOne: make(chan subscription),
		rooms:         make(map[string]map[*Client]bool),
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			connections := h.rooms[client.room]
			if connections == nil {
				connections = make(map[*Client]bool)
				h.rooms[client.room] = connections
			}
			h.rooms[client.room][client.conn] = true
		case client := <-h.unregister:
			for _, room := range client.rooms {
				connections := h.rooms[room]
				if connections != nil {
					if _, ok := connections[client.conn]; ok {
						delete(connections, client.conn)
						if len(connections) == 0 {
							delete(h.rooms, room)
						}
					}
				}
			}
			close(client.conn.send)
		case client := <-h.unregisterOne:
			connections := h.rooms[client.room]
			if connections != nil {
				if _, ok := connections[client.conn]; ok {
					delete(connections, client.conn)
					if len(connections) == 0 {
						delete(h.rooms, client.room)
					}
				}
			}
		case message := <-h.broadcast:
			fmt.Printf("rooms: %+v\n", h.rooms)
			connections := h.rooms[message.room]
			for client := range connections {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(connections, client)
					if len(connections) == 0 {
						delete(h.rooms, message.room)
					}
				}
			}
		}
	}
}

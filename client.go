// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub *Hub

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan message
}

type outMessage struct {
	ID         string `json:"id"`
	Body       string `json:"body"`
	SenderID   string `json:"senderID"`
	SendTime   string `json:"sendTime"`
	ReadStatus int    `json:"readStatus"`
}

type outPayload struct {
	Room    string     `json:"id"`
	Message outMessage `json:"message"`
}

type action struct {
	Type    int
	Payload string
}

type inMessage struct {
	Room    string
	Message string
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (s subscription) readPump() {
	fmt.Println("readPump")
	c := s.conn
	defer func() {
		fmt.Println("readPump defered!")
		c.hub.unregister <- s
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}
		msg = bytes.TrimSpace(bytes.Replace(msg, newline, space, -1))

		var action action
		err = json.Unmarshal(msg, &action)
		if err != nil {
			log.Printf("error: %v", err)
			break
		}
		fmt.Printf("action: %+v\n", action)

		if s.isExpired() && action.Type != 99 {
			fmt.Println("subscription expired and not auth action")
			return
		}

		switch action.Type {
		case 0:
			s.room = action.Payload
			for i, room := range s.rooms {
				if room == s.room {
					s.rooms = append(s.rooms[:i], s.rooms[i+1:]...)
					break
				}
			}
			c.hub.unregisterOne <- s
		case 1:
			// TODO: Check if user has this room
			if s.findRoom(action.Payload) {
				break
			}
			s.room = action.Payload
			s.rooms = append(s.rooms, action.Payload)
			c.hub.register <- s
		case 2:
			if s.room == "0" {
				log.Println("Did not set room.")
				return
			}
			var inMessage inMessage
			err := json.Unmarshal([]byte(action.Payload), &inMessage)
			if err != nil {
				log.Printf("error: %v", err)
				return
			}
			fmt.Printf("inMessage: %+v\n", inMessage)

			if s.findRoom(inMessage.Room) {
				m := message{[]byte(inMessage.Message), inMessage.Room, s.user.ID}
				c.hub.broadcast <- m
			} else {
				log.Println("Room does not match")
				return
			}
		case 99:
			token, err := jwt.Parse(action.Payload, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				return []byte(config.SECRET), nil
			})

			if err != nil {
				fmt.Println(err)
				return
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				fmt.Println(claims)

				// check exp time
				exp, ok := claims["exp"].(float64)
				if !ok {
					fmt.Println(claims["exp"])
					return
				}

				s.exp = int64(exp)

				id, ok := claims["id"].(string)
				if !ok {
					return
				}
				username, ok := claims["username"].(string)
				if !ok {
					return
				}
				email, ok := claims["email"].(string)
				if !ok {
					return
				}

				s.user = ChatUser{id, username, email}
				fmt.Printf("%+v\n", s)
				// TODO: send auth success
			} else {
				// TODO: send auth failed
				fmt.Println("token not valid")
				return
			}
		default:
			fmt.Println("TODO: Implement")
		}
	}
}

// writePump pumps messages from the hub to the websocket connection.
//
// A goroutine running writePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
func (s subscription) writePump() {
	fmt.Println("writePump")
	c := s.conn
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		fmt.Println("writePump defered!")
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}

			payload := createOutPayload(message)

			b, err := json.Marshal(payload)

			if err != nil {
				fmt.Println(err)
				return
			}
			w.Write(b)

			// Add queued chat messages to the current websocket message.
			n := len(c.send)
			fmt.Println("n: ", n)
			for i := 0; i < n; i++ {
				message, ok := <-c.send
				if !ok {
					c.conn.WriteMessage(websocket.CloseMessage, []byte{})
					return
				}

				payload := createOutPayload(message)

				b, err := json.Marshal(payload)

				if err != nil {
					fmt.Println(err)
					return
				}
				w.Write(newline)
				w.Write(b)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (s subscription) findRoom(val string) bool {
	for _, room := range s.rooms {
		if room == val {
			return true
		}
	}
	return false
}

func (s subscription) isExpired() bool {
	return time.Now().Unix() > s.exp
}

// serveWs handles websocket requests from the peer.
func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	client := &Client{hub: hub, conn: conn, send: make(chan message, 256)}

	rooms := []string{}
	s := subscription{client, "0", rooms, ChatUser{}, 0}
	// client.hub.register <- s

	// Allow collection of memory referenced by the caller by doing all work in
	// new goroutines.
	go s.writePump()
	go s.readPump()
}

func createOutPayload(m message) outPayload {
	om := outMessage{time.Now().UTC().Format(time.RFC3339Nano), string(m.body), m.sender, time.Now().UTC().Format(time.RFC3339), 0}
	fmt.Println("writePump outMessage: ", om)

	payload := outPayload{m.room, om}
	fmt.Println("writePump outChat: ", payload)

	return payload
}

package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/handlers"

	"github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var config Configuration

type Configuration struct {
	APP           string
	PORT          string
	DB_CONNECTION string
	SECRET        string
	ALLOW_ORIGIN  string
}

type Chat struct {
	ID       string    `json:"id"`
	Users    []string  `json:"users"`
	Messages []Message `json:"messages"`
}

type Message struct {
	ID         int64  `json:"id"`
	Body       string `json:"body"`
	SenderID   int64  `json:"sender_id"`
	SendTime   string `json:"send_time"`
	ReadStatus int    `json:"read_status"`
}

type ChatUser struct {
	ID       string
	Username string
	Email    string
}

func main() {
	file, err := os.Open("config/config.development.json")
	if err != nil {
		log.Fatalf(err.Error())
	}
	err = json.NewDecoder(file).Decode(&config)
	if err != nil {
		log.Fatalf(err.Error())
	}
	file.Close()

	db, err = sql.Open("mysql", config.DB_CONNECTION)
	if err != nil {
		log.Fatalf(err.Error())
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf(err.Error())
	}

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte(config.SECRET), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
	})

	originsOk := handlers.AllowedOrigins([]string{config.ALLOW_ORIGIN})
	headersOk := handlers.AllowedHeaders([]string{"Content-Type", "Authorization"})

	hub := newHub()
	go hub.run()

	r := mux.NewRouter()
	r.HandleFunc("/users/signup", signup).Methods("POST")
	r.HandleFunc("/users/signin", signin).Methods("POST")
	r.Handle("/users/{id}/chats", jwtMiddleware.Handler(getChatsHandler)).Methods("GET")
	r.Handle("/users/{id}/chats/{chat_id}/messages", jwtMiddleware.Handler(getChatMessagesHandler)).Methods("GET")
	r.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})
	fmt.Println("Server starting on port", config.PORT)
	log.Fatal(http.ListenAndServe(config.PORT, handlers.CORS(originsOk, headersOk)(handlers.LoggingHandler(os.Stdout, r))))
}

func errorWriter(w http.ResponseWriter, status int, message string) {
	switch status {
	case 400:
		http.Error(w, message, http.StatusBadRequest)
	case 401:
		http.Error(w, message, http.StatusUnauthorized)
	case 403:
		http.Error(w, message, http.StatusForbidden)
	case 404:
		http.Error(w, message, http.StatusNotFound)
	case 500:
		http.Error(w, message, http.StatusInternalServerError)
	default:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func getClaimsFromToken(r *http.Request) (jwt.MapClaims, error) {
	user, ok := r.Context().Value("user").(*jwt.Token)
	if !ok {
		return nil, errors.New("Invalid token")
	}
	claims := user.Claims.(jwt.MapClaims)
	return claims, nil
}

var getChatsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims, err := getClaimsFromToken(r)
	if err != nil {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}
	claimsID, ok := claims["id"].(string)
	if !ok {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}
	vars := mux.Vars(r)
	if vars["id"] != claimsID {
		errorWriter(w, 403, http.StatusText(http.StatusForbidden))
		return
	}
	rows, err := db.Query(
		`SELECT t1.chat_id, username, message_id, body, sender_id, send_time, read_status
		FROM chat_user_chat t1
		INNER JOIN chat_user_chat t2 ON t1.chat_id=t2.chat_id AND t1.chat_user_id!=?
		INNER JOIN chat_user t3 ON t1.chat_user_id=t3.id
		INNER JOIN chat t4 ON t4.id=t1.chat_id
		INNER JOIN message t5 ON t5.id=t4.last_message_id
		INNER JOIN chat_user_chat_message t6 ON t6.message_id=t4.last_message_id AND t6.chat_user_id=?
		WHERE t2.chat_user_id=?`, claims["id"], claims["id"], claims["id"])
	if err != nil {
		errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
		return
	}
	defer rows.Close()
	var chatID int64
	var username string
	var messageID int64
	var body string
	var senderID int64
	var sendTime string
	var readStatus int
	chats := []Chat{}
	for rows.Next() {
		err := rows.Scan(&chatID, &username, &messageID, &body, &senderID, &sendTime, &readStatus)
		if err != nil {
			errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
			return
		}
		users := []string{username}
		messages := []Message{Message{messageID, body, senderID, sendTime, readStatus}}
		chats = append(chats, Chat{strconv.FormatInt(chatID, 10), users, messages})
	}

	err = rows.Err()
	if err != nil {
		errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
		return
	}

	fchats := []Chat{}
	for i := 0; i < len(chats); i++ {
		item := chats[i]
		//Remove item
		chats = append(chats[:i], chats[i+1:]...)
		i--
		for j := 0; j < len(chats); j++ {
			item2 := chats[j]
			if item.ID == item2.ID && item.Users[0] != item2.Users[0] {
				item.Users = append(item.Users, item2.Users[0])
				chats = append(chats[:j], chats[j+1:]...)
				j--
			}
		}
		fchats = append(fchats, item)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fchats)
})

var getChatMessagesHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims, err := getClaimsFromToken(r)
	if err != nil {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}
	claimsID, ok := claims["id"].(float64)
	if !ok {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}
	vars := mux.Vars(r)
	varsID, err := strconv.Atoi(vars["id"])
	if err != nil {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}
	if varsID != int(claimsID) {
		errorWriter(w, 403, http.StatusText(http.StatusForbidden))
		return
	}
	messageID, err := strconv.Atoi(r.FormValue("message_id"))
	if err != nil {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}
	rows, err := db.Query(
		`SELECT t1.id, body, sender_id, send_time, read_status
		FROM chat.message t1
		INNER JOIN chat.chat_user_chat_message t2 ON t1.id = t2.message_id 
		WHERE t2.chat_user_chat_id=? AND t2.chat_user_id=? AND t1.id < ? LIMIT 25`, vars["chat_id"], claims["id"], messageID)
	if err != nil {
		errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
		return
	}
	defer rows.Close()
	var id int64
	var body string
	var senderID int64
	var sendTime string
	var readStatus int
	messages := []Message{}
	for rows.Next() {
		err := rows.Scan(&id, &body, &senderID, &sendTime, &readStatus)
		if err != nil {
			errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
			return
		}
		messages = append(messages, Message{id, body, senderID, sendTime, readStatus})
	}

	err = rows.Err()
	if err != nil {
		errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
})

func signup(w http.ResponseWriter, r *http.Request) {
	var data map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}
	password, ok := data["password"].(string)
	if !ok {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}
	username, ok := data["username"].(string)
	if !ok {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}
	email, ok := data["email"].(string)
	if !ok {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
		return
	}

	stmt, err := db.Prepare("INSERT INTO chat_user (username, email, password) VALUES(?, ?, ?)")
	if err != nil {
		errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
		return
	}
	res, err := stmt.Exec(username, email, bytes)
	if err != nil {
		errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
		return
	}
	lastID, err := res.LastInsertId()
	if err != nil {
		errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
		return
	}

	token := generateToken(lastID, username, email)
	tokenString, err := token.SignedString([]byte(config.SECRET))
	if err != nil {
		errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
		return
	}
	m := map[string]string{
		"token": tokenString,
	}
	json.NewEncoder(w).Encode(m)
}

func signin(w http.ResponseWriter, r *http.Request) {
	var data map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}
	password, ok := data["password"].(string)
	if !ok {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}
	email, ok := data["email"].(string)
	if !ok {
		errorWriter(w, 400, http.StatusText(http.StatusBadRequest))
		return
	}
	var hash string
	err = db.QueryRow("SELECT password FROM chat_user WHERE email=?", email).Scan(&hash)
	switch {
	case err == sql.ErrNoRows:
		errorWriter(w, 401, "Wrong username or password")
	case err != nil:
		errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
	default:
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		switch {
		case err == bcrypt.ErrMismatchedHashAndPassword:
			errorWriter(w, 401, "Wrong username or password")
		case err != nil:
			errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
		default:
			var id2 int64
			var username2 string
			var email2 string
			err = db.QueryRow("SELECT id, username, email FROM chat_user WHERE email=?", email).Scan(&id2, &username2, &email2)
			if err != nil {
				errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
				return
			}
			token := generateToken(id2, username2, email2)
			tokenString, err := token.SignedString([]byte(config.SECRET))
			if err != nil {
				errorWriter(w, 500, http.StatusText(http.StatusInternalServerError))
				return
			}
			m := map[string]string{
				"token": tokenString,
			}
			json.NewEncoder(w).Encode(m)
		}
	}
}

func generateToken(id int64, username string, email string) *jwt.Token {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = strconv.FormatInt(id, 10)
	claims["username"] = username
	claims["email"] = email
	claims["iss"] = config.APP
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	return token
}

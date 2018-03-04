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
}

type Chat struct {
	Id        int64    `json:"id"`
	Users     []string `json:"users"`
	Body      string   `json:"body"`
	Send_time string   `json:"send_time"`
}

type Message struct {
	Id          int    `json:"id"`
	Body        string `json:"body"`
	Send_time   string `json:"send_time"`
	Read_status int    `json:"read_status"`
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

	r := mux.NewRouter()
	r.HandleFunc("/users/signup", logger(signup)).Methods("POST")
	r.HandleFunc("/users/signin", logger(signin)).Methods("POST")
	r.Handle("/users/{id}/chats", jwtMiddleware.Handler(getChatsHandler)).Methods("GET")
	r.Handle("/users/{id}/chats/{chat_id}/messages", jwtMiddleware.Handler(getChatMessagesHandler)).Methods("GET")
	fmt.Println("Server starting on port", config.PORT)
	log.Fatal(http.ListenAndServe(config.PORT, handlers.LoggingHandler(os.Stdout, r)))
}

func logger(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		defer func() {
			log.Println(r.Method, r.URL.Path, time.Since(start).Seconds()*1000, "ms")
		}()
		f(w, r)
	}
}

func ErrorWriter(w http.ResponseWriter, status int) {
	switch status {
	case 400:
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	case 401:
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	case 403:
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	case 404:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case 500:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
		ErrorWriter(w, 400)
		return
	}
	fmt.Println(claims)
	claimsID, ok := claims["id"].(float64)
	if !ok {
		ErrorWriter(w, 400)
		return
	}
	vars := mux.Vars(r)
	varsID, err := strconv.Atoi(vars["id"])
	if err != nil {
		ErrorWriter(w, 400)
		return
	}
	fmt.Println(varsID != int(claimsID))
	if varsID != int(claimsID) {
		ErrorWriter(w, 403)
		return
	}
	rows, err := db.Query(
		`SELECT t1.chat_id, username, body, send_time
		FROM chat_user_chat t1
		INNER JOIN chat_user_chat t2 ON t1.chat_id=t2.chat_id AND t1.chat_user_id!=?
		INNER JOIN chat_user t3 ON t1.chat_user_id=t3.id
		INNER JOIN chat t4 ON t4.id=t1.chat_id
		INNER JOIN message t5 ON t5.id=t4.last_message_id
		WHERE t2.chat_user_id=?`, claims["id"], claims["id"])
	if err != nil {
		fmt.Println(err)
		ErrorWriter(w, 500)
		return
	}
	defer rows.Close()
	var chat_id int64
	var username string
	var body string
	var send_time string
	chats := []Chat{}
	for rows.Next() {
		err := rows.Scan(&chat_id, &username, &body, &send_time)
		if err != nil {
			ErrorWriter(w, 500)
			return
		}
		users := []string{username}
		chats = append(chats, Chat{chat_id, users, body, send_time})
	}

	err = rows.Err()
	if err != nil {
		ErrorWriter(w, 500)
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
			if item.Id == item2.Id && item.Users[0] != item2.Users[0] {
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
		ErrorWriter(w, 400)
		return
	}
	claimsID, ok := claims["id"].(float64)
	if !ok {
		ErrorWriter(w, 400)
		return
	}
	vars := mux.Vars(r)
	varsID, err := strconv.Atoi(vars["id"])
	if err != nil {
		ErrorWriter(w, 400)
		return
	}
	if varsID != int(claimsID) {
		ErrorWriter(w, 403)
		return
	}
	rows, err := db.Query(
		`SELECT id, body, send_time, read_status 
		FROM chat.message t1 
		INNER JOIN chat.chat_user_chat_message t2 ON t1.id = t2.message_id 
		WHERE t2.chat_user_chat_id=? AND t2.chat_user_id=? LIMIT 25`, vars["chat_id"], claims["id"])
	if err != nil {
		ErrorWriter(w, 500)
		return
	}
	defer rows.Close()
	var id int
	var body string
	var send_time string
	var read_status int
	messages := []Message{}
	for rows.Next() {
		err := rows.Scan(&id, &body, &send_time, &read_status)
		if err != nil {
			ErrorWriter(w, 500)
			return
		}
		messages = append(messages, Message{id, body, send_time, read_status})
	}

	err = rows.Err()
	if err != nil {
		ErrorWriter(w, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
})

func signup(w http.ResponseWriter, r *http.Request) {
	var data map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		ErrorWriter(w, 400)
		return
	}
	password, ok := data["password"].(string)
	if !ok {
		ErrorWriter(w, 400)
		return
	}
	username, ok := data["username"].(string)
	if !ok {
		ErrorWriter(w, 400)
		return
	}
	email, ok := data["email"].(string)
	if !ok {
		ErrorWriter(w, 400)
		return
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		ErrorWriter(w, 500)
		return
	}

	stmt, err := db.Prepare("INSERT INTO chat_user (username, email, password) VALUES(?, ?, ?)")
	if err != nil {
		ErrorWriter(w, 500)
		return
	}
	res, err := stmt.Exec(username, email, bytes)
	if err != nil {
		ErrorWriter(w, 500)
		return
	}
	lastId, err := res.LastInsertId()
	if err != nil {
		ErrorWriter(w, 500)
		return
	}

	token := GenerateToken(lastId, username, email)
	tokenString, err := token.SignedString([]byte(config.SECRET))
	if err != nil {
		ErrorWriter(w, 500)
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
		ErrorWriter(w, 400)
		return
	}
	password, ok := data["password"].(string)
	if !ok {
		ErrorWriter(w, 400)
		return
	}
	email, ok := data["email"].(string)
	if !ok {
		ErrorWriter(w, 400)
		return
	}
	var hash string
	err = db.QueryRow("SELECT password FROM chat_user WHERE email=?", email).Scan(&hash)
	switch {
	case err == sql.ErrNoRows:
		ErrorWriter(w, 401)
	case err != nil:
		ErrorWriter(w, 500)
	default:
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		switch {
		case err == bcrypt.ErrMismatchedHashAndPassword:
			ErrorWriter(w, 401)
		case err != nil:
			ErrorWriter(w, 500)
		default:
			var id2 int64
			var username2 string
			var email2 string
			err = db.QueryRow("SELECT id, username, email FROM chat_user WHERE email=?", email).Scan(&id2, &username2, &email2)
			if err != nil {
				ErrorWriter(w, 500)
				return
			}
			token := GenerateToken(id2, username2, email2)
			tokenString, err := token.SignedString([]byte(config.SECRET))
			if err != nil {
				ErrorWriter(w, 500)
				return
			}
			m := map[string]string{
				"token": tokenString,
			}
			json.NewEncoder(w).Encode(m)
		}
	}
}

func GenerateToken(id int64, username string, email string) *jwt.Token {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = id
	claims["username"] = username
	claims["email"] = email
	claims["iss"] = config.APP
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	return token
}

package main

import (
	"fmt"
	"net/http"
	"encoding/json"
	"log"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"github.com/gorilla/mux"
	"time"
	"github.com/dgrijalva/jwt-go"
	"os"
)

var db *sql.DB
var config Configuration

type Configuration struct {
	APP string
	PORT string
	DB_CONNECTION string
	SECRET string
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
	if (err != nil) {
		log.Fatalf(err.Error())
	}

	err = db.Ping()
	if (err != nil) {
		log.Fatalf(err.Error())
	}

	r := mux.NewRouter()
	r.HandleFunc("/users/signup", logger(signup)).Methods("POST")
	r.HandleFunc("/users/signin", logger(signin)).Methods("POST")
	fmt.Println("Server starting on port", config.PORT)
	log.Fatal(http.ListenAndServe(config.PORT, r))
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
	case 500:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	default:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func signup(w http.ResponseWriter, r *http.Request) {
	var data map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if (err != nil) {
		ErrorWriter(w, 400)
		return
	}
	password, ok:=data["password"].(string)
	if !ok {
		ErrorWriter(w, 400)
		return
	}
	username, ok:=data["username"].(string)
	if !ok {
		ErrorWriter(w, 400)
		return
	}
	email, ok:=data["email"].(string)
	if !ok {
		ErrorWriter(w, 400)
		return
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if (err != nil) {
		ErrorWriter(w, 500)
		return
	}

	stmt, err := db.Prepare("INSERT INTO chat_user (username, email, password) VALUES(?, ?, ?)")
	if (err != nil) {
		ErrorWriter(w, 500)
		return
	}
	res, err := stmt.Exec(username, email, bytes)
	if (err != nil) {
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
	if (err != nil) {
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
	if (err != nil) {
		ErrorWriter(w, 400)
		return
	}
	password, ok:=data["password"].(string)
	if !ok {
		ErrorWriter(w, 400)
		return
	}
	email, ok:=data["email"].(string)
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
				if (err != nil) {
					ErrorWriter(w, 500)
					return
				}
				token := GenerateToken(id2, username2, email2)
				tokenString, err := token.SignedString([]byte(config.SECRET))
				if (err != nil) {
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
	claims["exp"] = time.Now().Add(time.Hour*24).Unix()
	return token
}
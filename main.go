package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log"
	"net/http"
	"os"

	"github.com/Ianj751/handlers"
	"github.com/Ianj751/helpers"
	"github.com/Ianj751/ratelimiter"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/time/rate"
)

func main() {
	_, err := os.Create("./totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatal("error creating database file: ", err)
	}
	db, err := sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatal("error connecting to database: ", err)
	}
	defer db.Close()
	if err = db.Ping(); err != nil || db == nil {
		log.Fatal("error establishing connection to database: ", err)
	}

	/* Initialize Keys Table */
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys( 
						kid INTEGER PRIMARY KEY AUTOINCREMENT, 
						key BLOB NOT NULL, 
						exp INTEGER NOT NULL);`)
	if err != nil {
		log.Fatal("error creating table: ", err)
	}
	/* Initialize Users Table */
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users(
						id INTEGER PRIMARY KEY AUTOINCREMENT, 
						username TEXT NOT NULL UNIQUE, 
						password_hash TEXT NOT NULL, 
						email TEXT UNIQUE,
						date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
						last_login TIMESTAMP );`)
	if err != nil {
		log.Fatal("error creating table: ", err)
	}
	/* Initialize Auth_logs table */
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS auth_logs(
    					id INTEGER PRIMARY KEY AUTOINCREMENT,
    					request_ip TEXT NOT NULL,
    					request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    					user_id INTEGER,  
    					FOREIGN KEY(user_id) REFERENCES users(id));`)
	if err != nil {
		log.Fatal("error creating table: ", err)
	}

	key := make([]byte, 32)

	if _, err := rand.Reader.Read(key); err != nil {
		log.Fatal("error generating encryption key: %w", err)
	}
	os.Setenv("NOT_MY_KEY", hex.EncodeToString(key))

	/*
		Generate 2 private Keys, one expired and one non expired and save them to the DB.
	*/
	err = helpers.GenerateDBKeys(db, true) //expired key
	if err != nil {
		log.Fatal("error creating keys for database: ", err)
	}
	err = helpers.GenerateDBKeys(db, false) //unexpired key
	if err != nil {
		log.Fatal("error creating keys for database: ", err)
	}

	handler := &handlers.AppHandler{Db: db}

	mux := http.NewServeMux()

	mux.HandleFunc("/auth", handler.HandleAuth)
	mux.HandleFunc("/.well-known/jwks.json", handler.HandleJwks)
	mux.HandleFunc("/register", handler.HandleRegister)

	handlerate := ratelimiter.RateLimiterMiddleware(mux, rate.Limit(1), 10)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", handlerate))

}

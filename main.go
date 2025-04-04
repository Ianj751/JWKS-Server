package main

import (
	"crypto/rand"
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/Ianj751/handlers"
	"github.com/Ianj751/helpers"
	_ "github.com/mattn/go-sqlite3"
)

/*
* TODO List:
*	- RateLimiter
*	- Store and retrieve keys from env
 */
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

	/*
		Generate 2 private Keys, one expired and one non expired and save them to the DB.
	*/
	err = helpers.GenerateDBKeys(db, true, key) //expired key
	if err != nil {
		log.Fatal("error creating keys for database: ", err)
	}
	helpers.GenerateDBKeys(db, false, key) //unexpired key
	if err != nil {
		log.Fatal("error creating keys for database: ", err)
	}

	handler := &handlers.AppHandler{Db: db, Key: key}

	http.HandleFunc("/auth", handler.HandleAuth)
	http.HandleFunc("/.well-known/jwks.json", handler.HandleJwks)
	http.HandleFunc("/register", handler.HandleRegister)

	log.Fatal(http.ListenAndServe(":8080", nil))

}

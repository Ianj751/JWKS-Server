package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/Ianj751/handlers"
	"github.com/Ianj751/helpers"
	_ "github.com/mattn/go-sqlite3"
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

	/* Initialize Table */
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS `keys`( `kid` INTEGER PRIMARY KEY AUTOINCREMENT, `key` BLOB NOT NULL, `exp` INTEGER NOT NULL);")
	if err != nil {
		log.Fatal("error creating table: ", err)
	}
	/*
		Generate 2 private Keys, one expired and one non expired and save them to the DB.
	*/
	err = helpers.GenerateDBKeys(db, true) //expired key
	if err != nil {
		log.Fatal("error creating keys for database: ", err)
	}
	helpers.GenerateDBKeys(db, false) //unexpired key
	if err != nil {
		log.Fatal("error creating keys for database: ", err)
	}
	/* Shout out to claude for this solution */
	handler := &handlers.AppHandler{Db: db}

	http.HandleFunc("/auth", handler.HandleAuth)
	http.HandleFunc("/.well-known/jwks.json", handler.HandleJwks)
	http.HandleFunc("/register", handler.HandleRegister)

	log.Fatal(http.ListenAndServe(":8080", nil))

}

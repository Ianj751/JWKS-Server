package handlers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

type arg2params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func (h *AppHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Request method is not Allowed. Use Method POST Instead", http.StatusMethodNotAllowed)
		return
	}

	bytedata, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("error reading request body: %v", err), http.StatusInternalServerError)
	}

	data := map[string]interface{}{}
	err = json.Unmarshal(bytedata, &data)
	if err != nil {
		http.Error(w, fmt.Sprintf("error unmarshalling json data: %v", err), http.StatusInternalServerError)
	}
	user, ok := data["username"]
	if !ok {
		http.Error(w, "POST Request missing username parameter", http.StatusBadRequest)
		return
	}
	email, ok := data["email"]
	if !ok {
		http.Error(w, "POST Request missing email parameter", http.StatusBadRequest)
		return
	}

	p := arg2params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   32,
	}
	password := uuid.New()
	byteHash, err := generateFromPassword(password.String(), p)
	if err != nil {
		http.Error(w, fmt.Sprintf("error hashing password: %v", err), http.StatusInternalServerError)
		return
	}
	//Assuming this needs to be a string based on the type of the column
	strPass := fmt.Sprintf("%X", byteHash)

	/*
		CREATE TABLE IF NOT EXISTS users(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			email TEXT UNIQUE,
			date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_login TIMESTAMP
		);
	*/
	h.Db.Exec("INSERT INTO users (username, password_hash, email, last_login)VALUES(?, ?, ?, ?)", user, strPass, email, time.Now())

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(
		map[string]interface{}{
			"password": password,
		})

}

func generateFromPassword(password string, p arg2params) (hash []byte, err error) {

	salt, err := generateRandomBytes(p.saltLength)
	if err != nil {
		return nil, err
	}

	hash = argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	return hash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

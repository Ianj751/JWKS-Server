package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"net/http"
	"time"

	"github.com/Ianj751/helpers"
)

type auth_logs struct {
	ID                int
	Request_ip        string
	Request_timestamp time.Time
	User_id           int
}
type Users struct {
	ID              int
	Username        string
	Password_hash   string
	Email           string
	Date_registered int64
	Last_login      int64
}

func (h *AppHandler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Request method is not Allowed. Use Method Post Instead", http.StatusMethodNotAllowed)

		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	err := logAuthRequest(h.Db, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("error logging auth request: %v", err), http.StatusInternalServerError)
	}
	params := r.URL.Query()
	_, ok := params["expired"]
	paramValue := params.Get("expired")

	if !ok || paramValue != "true" {

		dbkey, err := helpers.GetDBKey(h.Db, false, h.Key)
		if err != nil {
			http.Error(w, "error generating token: "+err.Error(), http.StatusInternalServerError)

			return
		}
		tokenstr, err := helpers.DBKeytoJWT(dbkey)
		if err != nil {
			http.Error(w, "error converting private key to jwt: "+err.Error(), http.StatusInternalServerError)

			return
		}
		//convert key to jwt
		data := map[string]interface{}{
			"jwt": tokenstr,
		}
		encoder.Encode(data)
	} else { // localhost:8080/auth?expired=true
		// Generate the expired JWT
		dbkey, err := helpers.GetDBKey(h.Db, true, h.Key)
		if err != nil {
			http.Error(w, "error generating token: "+err.Error(), http.StatusInternalServerError)

			return
		}
		tokenstr, err := helpers.DBKeytoJWT(dbkey)
		if err != nil {
			http.Error(w, "error converting private key to jwt: "+err.Error(), http.StatusInternalServerError)

			return
		}

		// return an expired JWT with the expired key pair and expired expiry

		data := map[string]interface{}{
			"jwt":    tokenstr,
			"expiry": dbkey.Exp,
		}
		encoder.Encode(data)
	}
}

func logAuthRequest(db *sql.DB, r *http.Request) error {
	al := auth_logs{
		Request_timestamp: time.Now(),
		Request_ip:        r.RemoteAddr,
	}

	rows, err := db.Query("SELECT id FROM users;")
	if err != nil {
		return fmt.Errorf("error querying database for user: %w", err)
	}
	defer rows.Close()
	var userRows []Users
	for rows.Next() {
		user := Users{}
		if err := rows.Scan(&user.ID); err != nil {
			return fmt.Errorf("error copying rows into values: %w", err)
		}
		userRows = append(userRows, user)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating through rows: %w", err)
	}
	if len(userRows) != 1 {
		return fmt.Errorf("error querying database: more than one user available")
	}
	al.User_id = userRows[0].ID

	/* CREATE TABLE IF NOT EXISTS auth_logs(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	request_ip TEXT NOT NULL,
	request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	user_id INTEGER,
	FOREIGN KEY(user_id) REFERENCES users(id)); */
	db.Exec("INSERT INTO auth_logs (id, request_ip, request_timestamp, user_id) VALUES(?, ?, ?, ?)", al.ID, al.Request_ip, al.Request_timestamp, al.User_id)

	return nil
}

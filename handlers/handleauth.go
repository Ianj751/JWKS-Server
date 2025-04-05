package handlers

import (
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"net/http"
	"time"

	"github.com/Ianj751/helpers"
	"golang.org/x/crypto/argon2"
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

		dbkey, err := helpers.GetDBKey(h.Db, false)
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
		dbkey, err := helpers.GetDBKey(h.Db, true)
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

	bytebody, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("error reading request body: %w", err)
	}

	data := map[string]interface{}{}
	err = json.Unmarshal(bytebody, &data)
	if err != nil {
		return fmt.Errorf("error unmarshalling json data: %w", err)
	}
	user, ok := data["username"].(string)
	if !ok {
		return fmt.Errorf("error logging request: request missing username parameter")

	}
	pass, ok := data["password"].(string)
	if !ok {
		return fmt.Errorf("error logging request: request missing password parameter")
	}
	al.User_id, err = authNUser(db, user, pass)
	if err != nil {
		return fmt.Errorf("error logging request: %w", err)
	}

	db.Exec("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES(?, ?, ?)", al.Request_ip, al.Request_timestamp, al.User_id)

	return nil
}

/* Verifies identity of the user, returns id if successfully found, -1 if not found
 */
func authNUser(db *sql.DB, username string, password string) (int, error) {
	if username == "" || password == "" {
		return -1, fmt.Errorf("error authenticating user: username and/or password was empty")
	}
	rows, err := db.Query("SELECT id, password_hash FROM users WHERE username = ?", username)
	if err != nil {
		return -1, fmt.Errorf("error querying database for user: %w", err)
	}
	defer rows.Close()
	var userRows []Users
	for rows.Next() {
		user := Users{}
		if err := rows.Scan(&user.ID, &user.Password_hash); err != nil {
			return -1, fmt.Errorf("error copying rows into values: %w", err)
		}
		userRows = append(userRows, user)
	}
	if err := rows.Err(); err != nil {
		return -1, fmt.Errorf("error iterating through rows: %w", err)
	}

	if len(userRows) != 1 {
		return -1, fmt.Errorf("error authenticating user: username was not unique")
	}

	p, salt, hash, err := decodeHash(userRows[0].Password_hash)
	if err != nil {
		return -1, fmt.Errorf("error authenticating user: %w", err)
	}

	// Derive the key from the other password using the same parameters.
	otherHash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// Check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return userRows[0].ID, nil
	}
	return -1, nil

}

func decodeHash(encodedHash string) (p *Arg2params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, fmt.Errorf("error decoding hash: hash does not contain valid parameters")
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("error decoding hash: invalid version of argon2")
	}

	p = &Arg2params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.saltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.keyLength = uint32(len(hash))

	return p, salt, hash, nil
}

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

type JWK struct {
	Alg string    `json:"alg"` //algorithm intended for use with the key (RS256)
	Kty string    `json:"kty"` //algorithm family used with the key (this will be RSA)
	N   string    `json:"n"`   //rsa modulus
	E   string    `json:"e"`   //rsa public exponent
	Kid string    `json:"kid"` //key id
	Exp time.Time `json:"exp"`
}
type JWKS struct {
	Keys []JWK `json:"keys"`
}
type DBKeys struct {
	Kid int
	Key []byte
	Exp int
}

var (
	kid int = 0
	db  *sql.DB
)

func NewJWK(public rsa.PublicKey) JWK {
	kid += 1
	return JWK{
		"RS256", //alg
		"RSA",   //kty
		base64.RawURLEncoding.EncodeToString(public.N.Bytes()),                    //base64.RawURLEncoding.EncodeToString(public.N.Bytes()),//N
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()), //base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()), //E
		fmt.Sprint(kid),               //kid, RFC 7517 example A.1 uses a date here
		time.Now().Add(1 * time.Hour), //expiration date, set for an hour from now
	}
}

func generateRSAKeys() (*rsa.PrivateKey, error) {
	//RSA key pair is a set of public and private keys
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}
func DBKeytoJWT(key DBKeys) (string, error) {
	privKey, err := x509.ParsePKCS1PrivateKey(key.Key)
	if err != nil {
		return "", fmt.Errorf("error parsing pkcs1 form: %w", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(int64(key.Exp), 0)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		})
	token.Header["kid"] = key.Kid

	str, err := token.SignedString(privKey)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}
	return str, nil

}

func getDBKey(isExpired bool) (DBKeys, error) {
	var privateKeys []DBKeys
	rows, err := db.Query("SELECT * FROM keys;", time.Now().Unix())
	if err != nil {
		return DBKeys{}, fmt.Errorf("error retrieving keys from database: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var privs DBKeys
		if err := rows.Scan(&privs.Kid, &privs.Key, &privs.Exp); err != nil {
			return DBKeys{}, fmt.Errorf("error copying rows into values: %w", err)
		}
		privateKeys = append(privateKeys, privs)
	}
	if err := rows.Err(); err != nil {
		return DBKeys{}, fmt.Errorf("error iterating through rows: %w", err)
	}
	if isExpired {
		//if is expired return key with expiration date before now
		for _, key := range privateKeys {
			if time.Now().Before(time.Unix(int64(key.Exp), 0)) {
				return key, nil
			}
		}
	} else {
		for _, key := range privateKeys {
			if time.Now().After(time.Unix(int64(key.Exp), 0)) {
				return key, nil
			}
		}
	}
	return DBKeys{}, fmt.Errorf("should be impossible to reach this path")

}

/*
	A /auth endpoint that returns an unexpired, signed JWT on a POST request.

If the “expired” query parameter is present, issue a JWT signed with the expired key pair and the expired expiry.
*/
func HandleAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Request method is not Allowed. Use Method Post Instead", http.StatusMethodNotAllowed)
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	params := r.URL.Query()
	_, ok := params["expired"]
	paramValue := params.Get("expired")

	if !ok || paramValue != "true" {

		dbkey, err := getDBKey(false)
		if err != nil {
			http.Error(w, "error generating token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		tokenstr, err := DBKeytoJWT(dbkey)
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
		dbkey, err := getDBKey(false)
		if err != nil {
			http.Error(w, "error generating token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		tokenstr, err := DBKeytoJWT(dbkey)
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

/*
	A RESTful JWKS endpoint that serves the public keys in JWKS format.

Only serve keys that have not expired.

Reads all valid (non-expired) private keys from the DB.
Creates a JWKS response from those private keys.
*/
func HandleJwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Request method is not Allowed. Use Method Get Instead", http.StatusMethodNotAllowed)
		return
	}

	//TODO: Create response from privateKeys
	//Get list of unexpired keys from getDBKey

	jwks := JWKS{Keys: nil}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(jwks)
}
func generateDBKeys(isExpired bool) error {
	timeToAdd := time.Hour * 1
	if isExpired {
		timeToAdd *= -1
	}
	privateKey, err := generateRSAKeys()
	if err != nil {
		return fmt.Errorf("error generating rsa keys: %w", err)
	}
	PKCS1 := x509.MarshalPKCS1PrivateKey(privateKey)
	_, err = db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?);", PKCS1, time.Now().Add(timeToAdd))
	if err != nil {
		return fmt.Errorf("error inserting private key into database: %w", err)
	}
	return nil
}

func main() {
	db, err := sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()
	/* Initialize Table */
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS `keys`( `kid` INTEGER PRIMARY KEY AUTOINCREMENT, `key` BLOB NOT NULL, `exp` INTEGER NOT NULL);")
	if err != nil {
		log.Fatal("error creating table: ", err)
	}
	/*
		Generate 2 private Keys, one expired and one non expired and save them to the DB.
	*/
	err = generateDBKeys(true) //expired key
	if err != nil {
		log.Fatal("error creating keys for database: ", err)
	}
	generateDBKeys(false) //unexpired key
	if err != nil {
		log.Fatal("error creating keys for database: ", err)
	}

	http.HandleFunc("/auth", HandleAuth)
	http.HandleFunc("/.well-known/jwks.json", HandleJwks)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

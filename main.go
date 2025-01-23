package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/google/uuid"
)

/*TODO: Create a JWK store */
type JWK struct{
	Alg string `json:"alg"` //algorithm intended for use with the key (RS256)
	Kty string `json:"kty"` //algorithm family used with the key (this will be RSA)
	N *big.Int `json:"n"`//rsa modulus
	E int `json:"e"`//rsa public exponent
	Kid uuid.UUID `json:"kid"` //key id 
	Exp time.Time `json:"exp"`
}
type JWKS struct{
	Keys []JWK `json:"keys"`
}

//
func NewJWK(public rsa.PublicKey)JWK{
	return JWK{
		"RS256", //alg
		"RSA", //kty
		public.N, //N
		public.E, //E
		uuid.New(), //kid, RFC 7517 example A.1 uses a date here
		time.Now().AddDate(0, 0, 1), //expiration date, set for a day from now
	}
}

func keyIsExpired(key JWK)bool{
	//returns true if key is expired
	return time.Now().After(key.Exp)
}
func generateRSAKeys()(*rsa.PrivateKey, rsa.PublicKey){
	//RSA key pair is a set of public and private keys
	
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil{
		log.Fatal(err)
	}

	return privKey, privKey.PublicKey
}
/* A /auth endpoint that returns an unexpired, signed JWT on a POST request.
If the “expired” query parameter is present, issue a JWT signed with the expired key pair and the expired expiry. */
func handleAuth(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST"{
		http.Error(w, "Request method is not Allowed", http.StatusMethodNotAllowed)
	}
}

/* A RESTful JWKS endpoint that serves the public keys in JWKS format.
Only serve keys that have not expired.
 */
func handleJwks(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "application/json")
	_, rawKey := generateRSAKeys()
	key := NewJWK(rawKey)

	var keys []JWK

	if keyIsExpired(key){
		keys = append(keys, key)
	}
	jwks := JWKS{Keys:keys}

	json.NewEncoder(w).Encode(jwks)
}


func main(){
	http.HandleFunc("/auth", handleAuth)
	http.HandleFunc("/jwks", handleJwks)

	log.Fatal(http.ListenAndServe(":8080", nil))
}


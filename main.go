package main

/* TODO:
- Write Tests (look into fuzzing)
- Figure out if the post request will have parameters??
- Organize into different files
*/

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"

	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

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

//global keys variable 
var keys []JWK
var jwts []string

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
func generateJWT(expired bool)(string, rsa.PublicKey){
	numTime := 5 * time.Minute

	if expired{
		numTime = -numTime
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, 
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(numTime)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		})
	privk, _ := generateRSAKeys()
	str, err := token.SignedString(privk)
	if err != nil{
		log.Fatal(err)
	}
	return str, privk.PublicKey
}

/* A /auth endpoint that returns an unexpired, signed JWT on a POST request.
If the “expired” query parameter is present, issue a JWT signed with the expired key pair and the expired expiry. */
func handleAuth(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost{
		http.Error(w, "Request method is not Allowed", http.StatusMethodNotAllowed)
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	params := r.URL.Query()
	if _, ok := params["expired"]; ok{
		//return an expired jwt with the expired key pair and expired expiry
		tokenstr, _ := generateJWT(true)
		encoder.Encode(tokenstr)
	}else{
		tokenstr, pubk := generateJWT(false)
		/* Chat GPT prompt for the below jwt.Parse :
		how can i use jwt.parse if i used an rsa.privatekey with the signed string */
		token, err := jwt.Parse(tokenstr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return pubk, nil
		})
		if err != nil{
			log.Fatal(err)
		}
		expTime, _ := token.Claims.GetExpirationTime()
		data := map[string]interface{}{
			"jwt": tokenstr,
			"expiry":  expTime,
		}
		encoder.Encode(data)
		
	}
}
/* A RESTful JWKS endpoint that serves the public keys in JWKS format.
Only serve keys that have not expired.
 */
func handleJwks(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "application/json")
	_, rawKey := generateRSAKeys()
	key := NewJWK(rawKey)

	if !keyIsExpired(key){
		keys = append(keys, key)
	}
	jwks := JWKS{Keys:keys}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(jwks)
}


func main(){
	http.HandleFunc("/auth", handleAuth)
	http.HandleFunc("/jwks", handleJwks)

	log.Fatal(http.ListenAndServe(":8080", nil))
}


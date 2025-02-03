package main

/* TODO:
- Write remaining tests
*/
/* ISSUE:
gradebot error:

StdEncoding:
token is unverifiable: error while executing keyfunc: the given key ID was not found in the JWKS

URL Encoding
token has invalid claims: token is expired

run ./gradebot.exe project1 --debug
the key is literally there.
*/

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWK struct{
	Alg string `json:"alg"` //algorithm intended for use with the key (RS256)
	Kty string `json:"kty"` //algorithm family used with the key (this will be RSA)
	N string `json:"n"`//rsa modulus
	E string `json:"e"`//rsa public exponent
	Kid string `json:"kid"` //key id 
	Exp time.Time `json:"exp"`
}
type JWKS struct{
	Keys []JWK `json:"keys"`
}

 var(
	keys []JWK
	kid int = 0
	
	)


func NewJWK(public rsa.PublicKey)JWK{
	kid += 1
	return JWK{
		"RS256", //alg
		"RSA", //kty
		base64.RawURLEncoding.EncodeToString(public.N.Bytes()),//base64.RawURLEncoding.EncodeToString(public.N.Bytes()),//N
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),//base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()), //E
		fmt.Sprint(kid), //kid, RFC 7517 example A.1 uses a date here
		time.Now().Add(5 * time.Minute), //expiration date, set for a day from now
	}
}

func isKeyExpired(key JWK)bool{
	//returns true if key is expired
	return time.Now().After(key.Exp)
}
func generateRSAKeys()(*rsa.PrivateKey, error){
	//RSA key pair is a set of public and private keys
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil{
		return nil, err
	}

	return privKey, nil
}
func generateJWT(isExpired bool)(string, *rsa.PublicKey, error){
	numTime := 5 * time.Minute

	if isExpired{
		numTime = -numTime
	}

	privk, err := generateRSAKeys()
	if err != nil{
		return "", nil, fmt.Errorf("error generating RSA Keys: %w", err)
	}
	a := NewJWK(privk.PublicKey)
	

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, 
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(numTime)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
			
		})
	token.Header["kid"] = a.Kid
	
	
	keys = append(keys, a)

	str, err := token.SignedString(privk)
	if err != nil{
		return "", nil, fmt.Errorf("error signing token: %w", err)
	}

	return str, &privk.PublicKey, nil
}

/* A /auth endpoint that returns an unexpired, signed JWT on a POST request.
If the “expired” query parameter is present, issue a JWT signed with the expired key pair and the expired expiry. */
func HandleAuth(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost{
		http.Error(w, "Request method is not Allowed. Use Method Post Instead", http.StatusMethodNotAllowed)
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	params := r.URL.Query()
	_, ok := params["expired"]
	paramValue := params.Get("expired")
	
	if !ok || paramValue != "true"{
		
		tokenstr, pubk, err := generateJWT(false)
		if err != nil{
			http.Error(w, "error generating token: " + err.Error(), http.StatusInternalServerError)
			return
		}

		//This is really just to double check that the JWT is not expired.
		//jwt.Parse throws an error if it is expired
		_, err = jwt.Parse(tokenstr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return pubk, nil
		})
		if err != nil{
			http.Error(w, "error parsing token: " + err.Error(), http.StatusInternalServerError)
			return
		}
		
		data := map[string]interface{}{
			"jwt": tokenstr,
		}
		encoder.Encode(data)
	}else{ //localhost:8080/auth?expired=true
		tokenstr, pubk, err := generateJWT(true)
		if err != nil{
			http.Error(w, "error generating token: " + err.Error(), http.StatusInternalServerError)
			return
		}
		/* Chat GPT prompt for the below jwt.Parse :
		how can i use jwt.parse if i used an rsa.privatekey with the signed string */
		token, err := jwt.Parse(tokenstr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return pubk, nil
		})
		if err != nil && !errors.Is(err, jwt.ErrTokenExpired){
			http.Error(w, ("token unexpired: " + err.Error()), http.StatusInternalServerError )
			return
		}
		
		//return an expired jwt with the expired key pair and expired expiry
		expTime, err := token.Claims.GetExpirationTime()
		if err != nil{
			http.Error(w, "error obtaining token expiration: " + err.Error(), http.StatusInternalServerError)
			return
		}
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
func HandleJwks(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet{
		http.Error(w, "Request method is not Allowed. Use Method Get Instead", http.StatusMethodNotAllowed)
		return
	}

	var tmp JWKS
	for _, v := range keys{
		if !isKeyExpired(v){
			tmp.Keys = append(tmp.Keys, v)
		}
	}
	jwks := JWKS{Keys:tmp.Keys}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(jwks)
}


func main(){
	http.HandleFunc("/auth", HandleAuth)
	http.HandleFunc("/.well-known/jwks.json", HandleJwks)

	log.Fatal(http.ListenAndServe(":8080", nil))
}


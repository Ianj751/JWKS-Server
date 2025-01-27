package main

/* TODO:
- Write remaining tests
- gradebot error: token is unverifiable: error while executing keyfunc: the given key ID was not found in the JWKS
*/

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"time"

	"github.com/golang-jwt/jwt/v5"
	//"github.com/google/uuid"
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

//global keys variable 
var keys []JWK
var id int = 0

func NewJWK(public rsa.PublicKey)JWK{
	//i want an incrementing kid. 
	id += 1
	return JWK{
		"RS256", //alg
		"RSA", //kty
		public.N.String(), //N
		fmt.Sprintf("%d",public.E), //E
		fmt.Sprintf("%d", id), //kid, RFC 7517 example A.1 uses a date here
		time.Now().Add(5 * time.Minute), //expiration date, set for a day from now
	}
}

func isKeyExpired(key JWK)bool{
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
func generateJWT(expired bool)(string, *rsa.PublicKey){
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
	
	a := NewJWK(privk.PublicKey)
	token.Header["kid"]= a.Kid

	keys = append(keys, a)
	str, err := token.SignedString(privk)
	if err != nil{
		log.Fatal(err)
	}
	return str, &privk.PublicKey
}

/* A /auth endpoint that returns an unexpired, signed JWT on a POST request.
If the “expired” query parameter is present, issue a JWT signed with the expired key pair and the expired expiry. */
func HandleAuth(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost{
		http.Error(w, "Request method is not Allowed", http.StatusMethodNotAllowed)
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	
	params := r.URL.Query()
	if _, ok := params["expired"]; !ok{
		
		tokenstr, _ := generateJWT(false)
		data := map[string]interface{}{
			"jwt": tokenstr,
		}
		encoder.Encode(data)
	}else{ //localhost:8080/auth?expired=true
		tokenstr, pubk := generateJWT(true)
		/* Chat GPT prompt for the below jwt.Parse :
		how can i use jwt.parse if i used an rsa.privatekey with the signed string */
		token, err := jwt.Parse(tokenstr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return pubk, nil
		})
		if !errors.Is(err, jwt.ErrTokenExpired){
			log.Fatal("token unexpired. ", err)
		}
		
		//return an expired jwt with the expired key pair and expired expiry
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
func HandleJwks(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "application/json")
	/* _, rawKey := generateRSAKeys()
	key := NewJWK(rawKey)

	if !(key){
		keys = append(keys, key)
	} */
	var tmp []JWK
	for _, v := range keys{
		if !isKeyExpired(v){
			tmp = append(tmp, v)
		}
	}
	jwks := JWKS{Keys:tmp}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(jwks)
}


func main(){
	http.HandleFunc("/auth", HandleAuth)
	http.HandleFunc("/.well-known/jwks.json", HandleJwks)

	log.Fatal(http.ListenAndServe(":8080", nil))
}


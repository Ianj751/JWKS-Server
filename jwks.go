package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/google/uuid"
)

//members based on the RSA example in A.1 in https://datatracker.ietf.org/doc/rfc7517/
type pubkey struct{
	Alg string `json:"alg"` //algorithm intended for use with the key (RS256)
	Kty string `json:"kty"` //algorithm family used with the key (this will be RSA)
	N *big.Int `json:"n"`//rsa modulus
	E int `json:"e"`//rsa public exponent
	Kid string `json:"kid"` //key id The "x5u" (X.509 URL) parameter that refers to a resource for an X.509 public key certificate or certificate chain (...what?)
	Expired_at string `json:"expired_at"`
}
func NewPubKey(public rsa.PublicKey)pubkey{
	return pubkey{
		"RS256",
		"RSA",
		public.N,
		public.E,
		uuid.New().String(),
		time.Now().AddDate(0, 1, 0).String(), //Unsure 
	}
}

func generateRSAKeys()(*rsa.PrivateKey, rsa.PublicKey){
	//RSA key pair is a set of public and private keys
	
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil{
		log.Fatal(err)
	}

	return privKey, privKey.PublicKey
}
func handleAuth(w http.ResponseWriter, r *http.Request){
}

func main(){
	http.HandleFunc("/auth", handleAuth)

	err := http.ListenAndServe(":8080", nil)
	if err != nil{
		log.Fatal(err)
	}
}


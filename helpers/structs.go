package helpers

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"
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

func NewJWK(public rsa.PublicKey, kid int, exp int64) JWK {

	return JWK{
		"RS256", //alg
		"RSA",   //kty
		base64.RawURLEncoding.EncodeToString(public.N.Bytes()),                    //base64.RawURLEncoding.EncodeToString(public.N.Bytes()),//N
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()), //base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()), //E
		fmt.Sprint(kid),   //kid, RFC 7517 example A.1 uses a date here
		time.Unix(exp, 0), //expiration date, set for an hour from now
	}
}

type Users struct {
	ID              int
	Username        string
	Password_hash   string
	Email           string
	Date_registered int64
	Last_login      int64
}

type Auth_logs struct {
	ID                int
	Request_ip        string
	Request_timestamp int64
	User_id           int
}

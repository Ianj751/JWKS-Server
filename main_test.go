package main

import "testing"

/* import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
) */


func TestHandleAuthUnexpired(t *testing.T){
	//TODO: Write Test
	// Ensure that jwt returned is valid and in correct format
}
func TestHandleAuthExpired(t *testing.T){
	//TODO: Write Test
	//Ensure that the jwt is expired, in correct format, and contains expiry
}
func TestHandleJWKS(t *testing.T){
	//TODO: Write Test
	//Ensure that JWKS is correctly formatted, has appropriate members, and keys not expired
}
func TestGenerateJWT(t *testing.T){
	//TODO: Write Test
	//Kinda redundant but, ensure that jwt is valid and a valid public key is also returned
}
func TestGenerateRSA(t *testing.T){
	//TODO: Write Test
	//Ensure that RSA Keys are not invalid
}
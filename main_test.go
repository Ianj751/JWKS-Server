package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func segmentJWT(tokenstr string) ([]string, error) {
	result := strings.Split(tokenstr, ".")
	if len(result) != 3 {
		return nil, fmt.Errorf("failed to segment jwt")
	}
	return result, nil
}

func TestHandleAuthUnexpired(t *testing.T) {
	//Check if auth only responds to Post Requests
	req1 := httptest.NewRequest(http.MethodGet, "/auth", nil)
	w1 := httptest.NewRecorder()
	HandleAuth(w1, req1)

	if w1.Code != http.StatusMethodNotAllowed{
		t.Errorf("Expected error code 405, recieved %d", req1.Response.StatusCode)
	}
	// Ensure that jwt returned is valid and in correct format
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	w := httptest.NewRecorder()
	HandleAuth(w, req)
	if w.Code != http.StatusOK{
		t.Errorf("expected status code 200, got %d", w.Code)
	}
	body := w.Body.Bytes()

	var data map[string]interface{}
	json.Unmarshal(body, &data)
	//parse jwt

	tokenstr := data["jwt"].(string)
	//Does data[jwt] have valid header and payload?
	p := jwt.NewParser()
	splitJWT, err := segmentJWT(tokenstr)
	if err != nil {
		t.Error(err)
	}

	h, err := p.DecodeSegment(splitJWT[0])
	if err != nil {
		t.Error(err)
	}
	pL, err := p.DecodeSegment(splitJWT[1])
	if err != nil {
		t.Error(err)
	}

	//header has alg, kid, and typ
	var header map[string]interface{}
	json.Unmarshal(h, &header)
	if alg, ok := header["alg"]; !ok || alg != "RS256" {
		t.Error("header param 'alg' has invalid value", header)
	}
	if kid, ok := header["kid"]; !ok || kid == "" {
		t.Error("header param 'kid' has invalid value", header)
	}
	if typ, ok := header["typ"]; !ok || typ != "JWT" {
		t.Error("header param 'typ' has invalid value", header)
	}
	//payload has exp, iat
	var payload map[string]interface{}
	json.Unmarshal(pL, &payload)
	//big numbers get stored in scientific notation, 1.73862133e+09. This is a float64
	//have to convert then from float to int64
	if expFloat, ok := payload["exp"].(float64); ok {
		exp := int64(expFloat)
		if time.Now().After(time.Unix(exp, 0)) {
			t.Errorf("Token expired at %v", time.Unix(exp, 0))
		}
	} else {
		t.Error("payload param 'exp' is missing or not a valid number", payload)
	}

	if iatFloat, ok := payload["iat"].(float64); ok {
		iat := int64(iatFloat) // Convert from float64
		if time.Now().Before(time.Unix(iat, 0)) {
			t.Errorf("Token 'iat' is in the future: %v", time.Unix(iat, 0))
		}
	} else {
		t.Error("payload param 'iat' is missing or not a valid number", payload)
	}

}
func TestHandleAuthExpired(t *testing.T) {
	//Ensure that the jwt is expired, in correct format, and contains expiry
	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	w := httptest.NewRecorder()
	HandleAuth(w, req)
	if w.Code != http.StatusOK{
		t.Errorf("expected status code 200, got %d", w.Code)
	}
	body := w.Body.Bytes()
	

	data := map[string]interface{}{}
	json.Unmarshal(body, &data)

	expiryFloat, ok := data["expiry"].(float64)
	expiry := int64(expiryFloat)
	if !ok || time.Now().Before(time.Unix(expiry, 0)) {
		t.Error("expiry not found", data)
	}
	tokenstr, ok := data["jwt"].(string)
	if !ok {
		t.Error("jwt not found")
	}
	p := jwt.NewParser()
	splitJWT, err := segmentJWT(tokenstr)
	if err != nil {
		t.Error(err)
	}

	h, err := p.DecodeSegment(splitJWT[0])
	if err != nil {
		t.Error(err)
	}
	pL, err := p.DecodeSegment(splitJWT[1])
	if err != nil {
		t.Error(err)
	}

	//header has alg, kid, and typ
	var header map[string]interface{}
	json.Unmarshal(h, &header)
	if alg, ok := header["alg"]; !ok || alg != "RS256" {
		t.Error("header param 'alg' has invalid value", header)
	}
	if kid, ok := header["kid"]; !ok || kid == "" {
		t.Error("header param 'kid' has invalid value", header)
	}
	if typ, ok := header["typ"]; !ok || typ != "JWT" {
		t.Error("header param 'typ' has invalid value", header)
	}
	//payload has exp, iat
	var payload map[string]interface{}
	json.Unmarshal(pL, &payload)
	if expFloat, ok := payload["exp"].(float64); ok {
		exp := int64(expFloat)
		if time.Now().Before(time.Unix(exp, 0)) {
			t.Errorf("Token unexppired at %v", time.Unix(exp, 0))
		}
	} else {
		t.Error("payload param 'exp' is missing or not a valid number", payload)
	}

	if iatFloat, ok := payload["iat"].(float64); ok {
		iat := int64(iatFloat) // Convert from float64
		if time.Now().Before(time.Unix(iat, 0)) {
			t.Errorf("Token 'iat' is in the future: %v", time.Unix(iat, 0))
		}
	} else {
		t.Error("payload param 'iat' is missing or not a valid number", payload)
	}
}
func TestHandleJWKS(t *testing.T) {
	//Ensure that JWKS is correctly formatted, has appropriate members, and keys not expired
	//Make req to auth, authexpired check if keys present and correct members

	req1 := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	w1 := httptest.NewRecorder()
	HandleJwks(w1, req1)
	if w1.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status code 405, got: %d", w1.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	HandleJwks(w, req)
	if w.Code != http.StatusOK{
		t.Errorf("expected status code 200, got %d", w.Code)
	}
	body := w.Body.Bytes()

	var jwks JWKS
	err := json.Unmarshal(body, &jwks)
	if err != nil {
		t.Fatalf("error unmarshalling json: %v", err)
	}
	if jwks.Keys == nil {
		return
	}

	for i, key := range jwks.Keys {

		if key.Alg != "RS256" {
			t.Errorf("jwk parameter 'alg' not found at jwks index %d, key: %v", i, key)
		}
		//big.Int(0).Bytes() when base64rawurl encoded is "", if it is absent, it is the same
		if key.E == "" {
			t.Errorf("jwk parameter 'E' was zero or absent at jwks index %d, key: %v", i, key)
		}
		if key.Kid == "" {
			t.Errorf("jwk parameter 'kid' not found at jwks index %d, key: %v", i, key)
		}
		if key.Kty != "RSA" {
			t.Errorf("jwk parameter 'kty' was not RSA at jwks index %d, key: %v", i, key)
		}
		if key.N == "" {
			t.Errorf("jwk parameter 'N' not found at jwks index %d, key: %v", i, key)
		}
		if time.Now().After(key.Exp) {
			t.Errorf("key at index %d, was expired, key: %v", i, key)
		}
	}

}
func TestGenerateJWT(t *testing.T) {
	//Kinda redundant but, ensure that jwt is valid and a valid public key is also returned
	unexpJWT, unexpPubKey, err := generateJWT(false)
	if err != nil {
		t.Fatal("expected no error but got: ", err)
	}
	if unexpJWT == ""{
		t.Fatal("expected jwt to have contents but got an empty string")
	}
	if unexpPubKey == nil {
		t.Fatal("Expected a valid RSA public key, but got nil")
	}
	token, err := jwt.ParseWithClaims(unexpJWT, &jwt.RegisteredClaims{},func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return unexpPubKey, nil
	})
	if err != nil {
		t.Fatal("error parsing token: ", err)
	}
	if err != nil || !token.Valid {
		t.Fatalf("Expected a valid token, but got error: %v", err)
	}

	

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		t.Fatalf("Expected claims to be of type RegisteredClaims, got %T", claims)
	}

	if claims.ExpiresAt.Time.Before(time.Now()) {
		t.Fatal("Expected token to be valid but it's already expired")
	}
	

	if claims.IssuedAt == nil {
		t.Error("parameter 'iat' not found in JWT")
	} else {
		iatTime := claims.IssuedAt.Time
		if time.Now().Before(iatTime) {
			t.Errorf("JWT parameter 'iat' is in the future: %v", iatTime)
		}
	}

	expiredTokenStr, pubKeyExpired, err := generateJWT(true)
	if err != nil {
		t.Fatalf("Expected no error for expired token generation, but got: %v", err)
	}

	// Parse the expired token
	expiredToken, err := jwt.ParseWithClaims(expiredTokenStr, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return pubKeyExpired, nil
	})
	if err == nil && expiredToken.Valid {
		t.Fatal("Expected expired token to be invalid, but it's valid")
	}

	if expiredToken != nil {
		expiredClaims, ok := expiredToken.Claims.(*jwt.RegisteredClaims)
		if !ok {
			t.Fatal("Expected claims to be of type RegisteredClaims for expired token")
		}
		if expiredClaims.ExpiresAt.Time.After(time.Now()) {
			t.Fatal("Expected expired token's expiration time to be in the past")
		}
	}

}
func TestGenerateRSA(t *testing.T) {
	//Ensure that RSA Keys are not invalid
	//Reference RFC 8017
	key, err := generateRSAKeys()
	if err != nil || key == nil {
		t.Fatal("error generating rsa keys: ", err)
	}

	// n    the RSA modulus, a positive integer
	if key.N.Sign() != 1 {
		t.Error("invalid modulus")

	}
	// d   the RSA private exponent, a positive integer
	if key.D.Sign() != 1 {
		t.Error("invalid private exponent: ")
	}

	// e    the RSA public exponent, a positive integer
	/*, and the RSA
	  public exponent e is an integer between 3 and n - 1... */
	if key.E < 0 || key.E < 3 {
		t.Error("invalid public exponent, was not positive")
	}

	/* RFC 8017: In a valid RSA public key, the RSA modulus n is a product of u
	   distinct odd primes r_i, i = 1, 2, ..., u, where u >= 2...*/
	if len(key.Primes) < 2 {
		t.Error("not enough prime factors")
	}

	// Check if the key is valid by reconstructing some components

	if err := key.Validate(); err != nil {
		t.Errorf("key validation failed: %v", err)
	}

}



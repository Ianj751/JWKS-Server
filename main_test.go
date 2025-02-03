package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)
func makeRequest(method string, url string)([]byte, error){
	req, err := http.NewRequest(method, url, nil)
	if err != nil{
		return nil, fmt.Errorf("%w", err)
	}

	recorder := httptest.NewRecorder()
	HandleAuth(recorder, req)
	resp := recorder.Result()
	if resp.StatusCode != 200{
		return nil, fmt.Errorf("status code was not 200: recieved: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil{
		return nil, fmt.Errorf("%w", err)
	}
	

	return	body, nil
}
func segmentJWT(tokenstr string)([]string, error){
	result := strings.Split(tokenstr, ".")
	if len(result) != 3{
		return nil, fmt.Errorf("failed to segment jwt")
	}
	return result, nil
}

func TestHandleAuthUnexppired(t *testing.T){
	//TODO: Write Test
	// Ensure that jwt returned is valid and in correct format
	body, err := makeRequest(http.MethodPost, "http://localhost:8080/auth")
	if err != nil{
		t.Error(err)
	}

	var data map[string]interface{}
	json.Unmarshal(body, &data)
	//parse jwt
	
	tokenstr := data["jwt"].(string)
	//Does data[jwt] have valid header and payload?
	p := jwt.NewParser()
	splitJWT, err := segmentJWT(tokenstr)
	if err != nil{
		t.Error(err)
	}

	h, err := p.DecodeSegment(splitJWT[0])
	if err != nil{
		t.Error(err)
	}
	pL, err := p.DecodeSegment(splitJWT[1])
	if err != nil{
		t.Error(err)
	}

	//header has alg, kid, and typ
	var header map[string]interface{}
	json.Unmarshal(h, &header)
	if alg, ok := header["alg"]; !ok || alg != "RS256"{
		t.Error("header param 'alg' has invalid value", header)
	}
	if kid, ok := header["kid"]; !ok ||  kid == ""{
		t.Error("header param 'kid' has invalid value", header)
	}
	if typ, ok := header["typ"]; !ok || typ != "JWT"{
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
func TestHandleAuthExpired(t *testing.T){
	//Ensure that the jwt is expired, in correct format, and contains expiry
	body, err := makeRequest(http.MethodPost, "http://localhost:8080/auth?expired=true")
	if err != nil{
		t.Error(err)
	}

	data := map [string]interface{}{}
	json.Unmarshal(body, &data)
	
	expiryFloat, ok := data["expiry"].(float64)
	expiry := int64(expiryFloat)
	if !ok || time.Now().Before(time.Unix(expiry, 0)){
		t.Error("expiry not found", data)
	}
	tokenstr, ok := data["jwt"].(string)
	if !ok{
		t.Error("jwt not found")
	}
	p := jwt.NewParser()
	splitJWT, err := segmentJWT(tokenstr)
	if err != nil{
		t.Error(err)
	}

	h, err := p.DecodeSegment(splitJWT[0])
	if err != nil{
		t.Error(err)
	}
	pL, err := p.DecodeSegment(splitJWT[1])
	if err != nil{
		t.Error(err)
	}

	//header has alg, kid, and typ
	var header map[string]interface{}
	json.Unmarshal(h, &header)
	if alg, ok := header["alg"]; !ok || alg != "RS256"{
		t.Error("header param 'alg' has invalid value", header)
	}
	if kid, ok := header["kid"]; !ok ||  kid == ""{
		t.Error("header param 'kid' has invalid value", header)
	}
	if typ, ok := header["typ"]; !ok || typ != "JWT"{
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
func TestHandleJWKS(t *testing.T){
	//TODO: Write Test
	//Ensure that JWKS is correctly formatted, has appropriate members, and keys not expired
	body, err := makeRequest(http.MethodGet, "http://localhost:8080/.well-known/jwks.json")
	if err != nil{
		t.Error(err)
	}

	data := map [string]interface{}{}
	json.Unmarshal(body, &data)
}
func TestGenerateJWT(t *testing.T){
	//TODO: Write Test
	//Kinda redundant but, ensure that jwt is valid and a valid public key is also returned
	unexpJWT, unexpPubKey, err := generateJWT(false)
	if err != nil{
		t.Error(err)
	}
	/* token, err := jwt.Parse(unexpJWT, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return unexpPubKey, nil
	})
	if err != nil{
		t.Error("error parsing token: ", err)
	} */
	
}
func TestGenerateRSA(t *testing.T){
	//TODO: Write Test
	//Ensure that RSA Keys are not invalid
}
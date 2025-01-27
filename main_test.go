package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

//to find where the payload ends in a jwt
func TestHandleAuth(t *testing.T){
	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/auth", nil)
	if err != nil{
		t.Error(err)
	}
	recorder := httptest.NewRecorder()
	HandleAuth(recorder, req)
	resp := recorder.Result()
	byteBody, err := io.ReadAll(resp.Body)

	if err != nil{
		t.Error(err)
	}
	body := string(byteBody)

	if resp.StatusCode != 200{
		t.Error("Status code was not 200 ok")
	}
	//Test if it is an unexpired, signed JWT
	//jwts are base64 encoded. Utilizing this to decode the header and payload
	firstIndex := strings.IndexRune(body, '.')
	if firstIndex == -1 {
		t.Error("Could not find first period") // header not found
	}
	rawHeader := body[1:firstIndex]
	if len(rawHeader)%4 != 0 {
		rawHeader = rawHeader + strings.Repeat("=", 4-len(rawHeader)%4)
	}
	secondIndex := strings.IndexRune(body[firstIndex+1:], '.')
	if secondIndex == -1 {
		t.Error("Could not find second period") // payload not found
	}
	secondIndex = firstIndex + secondIndex + 1
	rawPayload := body[firstIndex + 1:secondIndex]
	//Apparently base64 strings require padding so if the length is not a multiple of 4
	if len(rawPayload)%4 != 0 {
		rawPayload = rawPayload + strings.Repeat("=", 4-len(rawPayload)%4)
	}

	decodedHeader, err := base64.StdEncoding.DecodeString(rawHeader)
	if err != nil{
		t.Error(err, rawHeader)
	}
	decodedPayload, err := base64.StdEncoding.DecodeString(rawPayload)
	if err != nil{
		t.Error(err, rawPayload)
	}

	var header map[string]interface{}
	json.Unmarshal(decodedHeader, &header)
	if _, ok := header["alg"]; !ok{
		t.Error("Could not find alg parameter in JWT")
	}else if header["alg"] != "RS256"{
		t.Error("Incorrect value for alg parameter in JWT")
	}
	if _, ok := header["typ"]; !ok{
		t.Error("Could not find typ parameter in JWT")
	}else if header["typ"] != "JWT"{
		t.Error("Incorrect value for typ parameter in JWT")
	}
	var payload map[string]interface{}
	json.Unmarshal(decodedPayload, &payload)
	if _, ok := payload["exp"]; !ok{
		t.Error("Could not find exp parameter in JWT")
	}
	if _, ok := payload["iat"]; !ok{
		t.Error("Could not find iat parameter in JWT")
	}
}
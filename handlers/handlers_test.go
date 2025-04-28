package handlers

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestHandleRegister(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()

	handler := &AppHandler{Db: db}

	m := map[string]string{
		"username": "user123",
		"email":    "user@example.com",
	}
	s, err := json.Marshal(m)
	if err != nil {
		t.Error("error marshalling json: ", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(s))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.HandleRegister(rec, req)

	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusCreated, rec.Code)
	}

	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("error unmarshalling response: %v", err)
	}

	if _, ok := response["password"]; !ok {
		t.Errorf("expected password in response, got %v", response)
	}

	uuidregex := `\w{8}-\w{4}-\w{4}-\w{4}-\w{12}`
	match, err := regexp.MatchString(uuidregex, response["password"].(string))
	if err != nil {
		t.Errorf("error matching regex: %v", err)
	}
	if !match {
		t.Errorf("could not match actual reponse: \"%v\" with expected regex: \"%s\"", response["password"], uuidregex)
	}
}

func TestHandleAuth(t *testing.T) {
	// Generate encryption key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("error generating encryption key:", err)
	}
	os.Setenv("NOT_MY_KEY", hex.EncodeToString(key))

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error generating RSA key: %v", err)
	}
	pkcs1PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("error creating cipher block: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("error creating GCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("error generating nonce: %v", err)
	}
	encryptedKey := gcm.Seal(nonce, nonce, pkcs1PrivateKey, nil)

	db, mock, _ := sqlmock.New()
	defer db.Close()

	mock.ExpectQuery(`SELECT id, password_hash FROM users WHERE username = \?`).
		WithArgs("John").
		WillReturnRows(sqlmock.NewRows([]string{"id", "password_hash"}).
			AddRow(1, `$argon2i$v=19$m=16,t=2,p=1$YXNkZmdoams$p1qo48CIXoQJjr27lsNDPQ`))

	mock.ExpectQuery(`SELECT \* FROM keys`).
		WillReturnRows(sqlmock.NewRows([]string{"kid", "key", "exp"}).
			AddRow(1, encryptedKey, 9999999999))

	handler := &AppHandler{Db: db}

	m := map[string]string{
		"username": "John",
		"password": "hi",
	}
	s, err := json.Marshal(m)
	if err != nil {
		t.Fatal("error marshalling json:", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewReader(s))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.HandleAuth(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d\n%s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("error unmarshalling response: %v", err)
	}

	if _, ok := response["jwt"]; !ok {
		t.Errorf("expected jwt in response, got %v", response)
	}
}

func TestHandleJwks(t *testing.T) {

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("error generating encryption key:", err)
	}
	os.Setenv("NOT_MY_KEY", hex.EncodeToString(key))

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error generating RSA key: %v", err)
	}

	pkcs1PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("error creating cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("error creating GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("error generating nonce: %v", err)
	}

	encryptedKey := gcm.Seal(nonce, nonce, pkcs1PrivateKey, nil)

	// Mock the database
	db, mock, _ := sqlmock.New()
	defer db.Close()

	handler := &AppHandler{Db: db}

	mock.ExpectQuery("SELECT .* FROM keys WHERE exp > \\?").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"kid", "key", "exp"}).
			AddRow(1, encryptedKey, 9999999999))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	handler.HandleJwks(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: \n%v", http.StatusOK, rec.Code, rec.Body.String())
	}

	var response map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("error unmarshalling response: %v", err)
	}

	if _, ok := response["keys"]; !ok {
		t.Errorf("expected keys in response, got %v", response)
	}
}

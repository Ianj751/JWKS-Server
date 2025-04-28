package helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestGenerateDBKeys(t *testing.T) {
	// Setup
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("error generating encryption key:", err)
	}
	os.Setenv("NOT_MY_KEY", hex.EncodeToString(key))

	tests := []struct {
		name    string
		expired bool
		wantErr bool
	}{
		{"generate unexpired key", false, false},
		{"generate expired key", true, false},
		{"generate with missing env var", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("error creating mock db: %v", err)
			}
			defer db.Close()

			if tt.name == "generate with missing env var" {
				os.Unsetenv("NOT_MY_KEY")
			}

			mock.ExpectExec("INSERT INTO keys \\(key, exp\\) VALUES \\(\\?, \\?\\)").
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(1, 1))

			err = GenerateDBKeys(db, tt.expired)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateDBKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeAESPK(t *testing.T) {

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("error generating encryption key:", err)
	}
	os.Setenv("NOT_MY_KEY", hex.EncodeToString(key))

	testData := []byte("test private key data")

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

	encryptedData := gcm.Seal(nonce, nonce, testData, nil)

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"valid data", encryptedData, false},
		{"invalid data", []byte("invalid"), true},
		{"empty data", []byte{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeAESPK(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeAESPK() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != string(testData) {
				t.Errorf("DecodeAESPK() = %v, want %v", string(got), string(testData))
			}
		})
	}
}

func TestGetExpiredDBKeys(t *testing.T) {

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error creating mock db: %v", err)
	}
	defer db.Close()

	now := time.Now().Unix()
	mockRows := sqlmock.NewRows([]string{"kid", "key", "exp"}).
		AddRow(1, []byte("key1"), now-1000)

	mock.ExpectQuery("SELECT \\* FROM keys WHERE exp <= \\?").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(mockRows)
}

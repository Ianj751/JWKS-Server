package helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"time"
)

func GenerateDBKeys(db *sql.DB, isExpired bool, key []byte) error {
	if db == nil {
		return fmt.Errorf("database connection was nil")
	}
	if err := db.Ping(); err != nil {
		return fmt.Errorf("error establishing database connection: %w", err)
	}
	timeToAdd := time.Hour * 1
	if isExpired {
		timeToAdd *= -1
	}
	privateKey, err := GenerateRSAKeys()
	if err != nil || privateKey == nil {
		return fmt.Errorf("error generating rsa keys: %w", err)
	}

	aesPKSC1, err := aesEncrypt(x509.MarshalPKCS1PrivateKey(privateKey), key)
	if err != nil {
		return fmt.Errorf("error encrypting private key: %w", err)
	}
	_, err = db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?);", aesPKSC1, time.Now().Add(timeToAdd).Unix())
	if err != nil {
		return fmt.Errorf("error inserting private key into database: %w", err)
	}
	return nil
}

func aesEncrypt(data []byte, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating aes block cipher: %w", err)
	}

	//Galois Counter mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error setting GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("error generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return ciphertext, nil
}

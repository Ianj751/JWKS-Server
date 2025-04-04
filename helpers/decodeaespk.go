package helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
)

/* This function's sole purpose is to decode the private keys retrieved from the database */
func DecodeAESPK(data []byte) ([]byte, error) {
	strkey := os.Getenv("NOT_MY_KEY")
	if strkey == "" {
		return nil, fmt.Errorf("error retrieving AES key: environment variable 'NOT_MY_KEY' was empty")
	}

	bytekey, err := hex.DecodeString(strkey)
	if err != nil {
		return nil, fmt.Errorf("error decoding AES key from env variable: %w", err)
	}

	c, err := aes.NewCipher(bytekey)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("error verifying nonce size: length of data was less than nonce")
	}

	nonce, data := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting ciphertext: %w", err)
	}

	return plaintext, nil
}

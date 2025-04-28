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
	strKey := os.Getenv("NOT_MY_KEY")
	if strKey == "" {
		return nil, fmt.Errorf("error getting environment variable: environment variable not set")
	}
	key, err := hex.DecodeString(strKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding environment variable %w", err)
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("error verifying nonce size: length of data(%d) was less than nonce(%d)", len(data), nonceSize)
	}

	nonce, data := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting ciphertext: %w", err)
	}

	return plaintext, nil
}

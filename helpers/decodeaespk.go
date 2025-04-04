package helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

/* This function's sole purpose is to decode the private keys retrieved from the database */
func DecodeAESPK(data []byte, key []byte) ([]byte, error) {

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
		return nil, fmt.Errorf("error verifying nonce size: length of data was less than nonce")
	}

	nonce, data := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting ciphertext: %w", err)
	}

	return plaintext, nil
}

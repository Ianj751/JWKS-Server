package helpers

import (
	"crypto/rand"
	"crypto/rsa"
)

func GenerateRSAKeys() (*rsa.PrivateKey, error) {
	//RSA key pair is a set of public and private keys
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

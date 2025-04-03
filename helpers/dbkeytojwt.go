package helpers

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func DBKeytoJWT(key DBKeys) (string, error) {
	privKey, err := x509.ParsePKCS1PrivateKey(key.Key)
	if err != nil {
		return "", fmt.Errorf("error parsing pkcs1 form: %w", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(int64(key.Exp), 0)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		})
	token.Header["kid"] = fmt.Sprint(key.Kid)

	str, err := token.SignedString(privKey)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}
	return str, nil

}

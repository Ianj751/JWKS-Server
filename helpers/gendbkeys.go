package helpers

import (
	"crypto/x509"
	"database/sql"
	"fmt"
	"time"
)

func GenerateDBKeys(db *sql.DB, isExpired bool) error {
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
	PKCS1 := x509.MarshalPKCS1PrivateKey(privateKey)
	_, err = db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?);", PKCS1, time.Now().Add(timeToAdd).Unix())
	if err != nil {
		return fmt.Errorf("error inserting private key into database: %w", err)
	}
	return nil
}

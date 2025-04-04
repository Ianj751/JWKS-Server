package helpers

import (
	"database/sql"
	"fmt"
	"time"
)

func GetAllDBKeys(db *sql.DB, key []byte) ([]DBKeys, error) {
	privateKeys := []DBKeys{}
	rows, err := db.Query("SELECT * FROM keys WHERE exp > ?;", time.Now().Unix())
	if err != nil {
		return nil, fmt.Errorf("error retrieving keys from database: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		privs := DBKeys{}
		if err := rows.Scan(&privs.Kid, &privs.Key, &privs.Exp); err != nil {
			return nil, fmt.Errorf("error copying rows into values: %w", err)
		}

		privs.Key, err = DecodeAESPK(privs.Key, key)
		if err != nil {
			return nil, fmt.Errorf("error decoding private key from database: %w", err)
		}
		privateKeys = append(privateKeys, privs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through rows: %w", err)
	}
	return privateKeys, nil
}

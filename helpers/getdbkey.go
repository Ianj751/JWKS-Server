package helpers

import (
	"database/sql"
	"fmt"
	"time"
)

func GetDBKey(db *sql.DB, isExpired bool) (DBKeys, error) {
	privateKeys := []DBKeys{}
	rows, err := db.Query("SELECT * FROM keys;")
	if err != nil {
		return DBKeys{}, fmt.Errorf("error retrieving keys from database: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		privs := DBKeys{}
		if err := rows.Scan(&privs.Kid, &privs.Key, &privs.Exp); err != nil {
			return DBKeys{}, fmt.Errorf("error copying rows into values: %w", err)
		}
		privateKeys = append(privateKeys, privs)
	}
	if err := rows.Err(); err != nil {
		return DBKeys{}, fmt.Errorf("error iterating through rows: %w", err)
	}
	if isExpired {
		//If now is before an expiration date then it is unexpired
		for _, key := range privateKeys {
			if time.Now().After(time.Unix(int64(key.Exp), 0)) {
				return key, nil
			}
		}
	} else {
		for _, key := range privateKeys {
			if time.Now().Before(time.Unix(int64(key.Exp), 0)) {
				return key, nil
			}
		}
	}
	return DBKeys{}, fmt.Errorf("should be impossible to reach this path")

}

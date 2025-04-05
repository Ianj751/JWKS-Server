package handlers

import "database/sql"

type AppHandler struct {
	Db *sql.DB
}

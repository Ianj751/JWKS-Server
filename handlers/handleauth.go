package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Ianj751/helpers"
)

func (h *AppHandler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Request method is not Allowed. Use Method Post Instead", http.StatusMethodNotAllowed)
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	params := r.URL.Query()
	_, ok := params["expired"]
	paramValue := params.Get("expired")

	if !ok || paramValue != "true" {

		dbkey, err := helpers.GetDBKey(h.Db, false)
		if err != nil {
			http.Error(w, "error generating token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		tokenstr, err := helpers.DBKeytoJWT(dbkey)
		if err != nil {
			http.Error(w, "error converting private key to jwt: "+err.Error(), http.StatusInternalServerError)
			return
		}
		//convert key to jwt
		data := map[string]interface{}{
			"jwt": tokenstr,
		}
		encoder.Encode(data)
	} else { // localhost:8080/auth?expired=true
		// Generate the expired JWT
		dbkey, err := helpers.GetDBKey(h.Db, true)
		if err != nil {
			http.Error(w, "error generating token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		tokenstr, err := helpers.DBKeytoJWT(dbkey)
		if err != nil {
			http.Error(w, "error converting private key to jwt: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// return an expired JWT with the expired key pair and expired expiry

		data := map[string]interface{}{
			"jwt":    tokenstr,
			"expiry": dbkey.Exp,
		}
		encoder.Encode(data)
	}
}

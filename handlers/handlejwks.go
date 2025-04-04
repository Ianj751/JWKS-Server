package handlers

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Ianj751/helpers"
)

func (h *AppHandler) HandleJwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Request method is not Allowed. Use Method Get Instead", http.StatusMethodNotAllowed)
		return
	}

	dbkeys, err := helpers.GetAllDBKeys(h.Db, h.Key)
	if err != nil {
		http.Error(w, fmt.Sprintf("error retrieving keys from database: %v", err), http.StatusInternalServerError)
		return
	}
	//Convert to JWKS
	jwkeys := []helpers.JWK{}
	var temp helpers.JWK
	for _, val := range dbkeys {
		pk, err := x509.ParsePKCS1PrivateKey(val.Key)
		if err != nil {
			http.Error(w, fmt.Sprintf("error converting blob to rsa key: %v", err), http.StatusInternalServerError)
			return
		}
		temp = helpers.NewJWK(pk.PublicKey, val.Kid, int64(val.Exp))
		jwkeys = append(jwkeys, temp)
	}

	jwks := helpers.JWKS{Keys: jwkeys}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(jwks)
}

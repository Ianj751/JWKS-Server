package handlers

import (
	"net/http"
)

func (h *AppHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Request method is not Allowed. Use Method POST Instead", http.StatusMethodNotAllowed)
		return
	}
}

// src/go/handlers/auth.go
// PASO 14: Timing Attack — crypto/subtle.ConstantTimeCompare para comparar tokens

package handlers

import (
	"crypto/subtle"
	"net/http"
	"os"
)

func getExpectedKey() string {
	key := os.Getenv("API_KEY")
	if key == "" {
		panic("API_KEY environment variable is required")
	}
	return key
}

func ValidateAPIKey(w http.ResponseWriter, r *http.Request) {
	provided := r.Header.Get("X-API-Key")
	expected := getExpectedKey()
	if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1 {
		w.Write([]byte("authorized"))
	} else {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
}

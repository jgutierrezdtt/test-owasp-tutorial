// src/go/handlers/auth.go
// PASO 14: Timing Attack — crypto/subtle.ConstantTimeCompare para comparar tokens

package handlers

import (
	"net/http"
	"os"
)

// VULNERABLE (punto de inicio del ejercicio):
// func ValidateAPIKey(w http.ResponseWriter, r *http.Request) {
//     provided := r.Header.Get("X-API-Key")
//     expected := getExpectedKey()
//     if provided == expected {
//         w.Write([]byte("authorized"))
//     } else {
//         http.Error(w, "unauthorized", http.StatusUnauthorized)
//     }
// }
//
// La comparacion con == termina en el primer byte diferente.
// Midiendo el tiempo de respuesta de miles de peticiones, un atacante puede
// deducir byte a byte el valor del token correcto sin conocerlo.

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
	if provided == expected {
		w.Write([]byte("authorized"))
	} else {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

// src/go/handlers/headers.go
// PASO 11: HTTP Header Injection — sanitizar valores de cabecera antes de escribirlos

package handlers

import (
	"net/http"
	"strings"
)

var allowedRedirects = map[string]bool{
	"/dashboard": true,
	"/profile":   true,
	"/settings":  true,
}

func sanitizeHeaderValue(v string) string {
	if strings.ContainsAny(v, "\r\n\t") {
		return ""
	}
	return v
}

func RedirectHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	safe := sanitizeHeaderValue(next)
	if !allowedRedirects[safe] {
		http.Error(w, "Destino no permitido", http.StatusBadRequest)
		return
	}
	w.Header().Set("Location", safe)
	w.WriteHeader(http.StatusFound)
}

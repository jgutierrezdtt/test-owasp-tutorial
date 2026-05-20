// src/go/handlers/headers.go
// PASO 11: HTTP Header Injection — sanitizar valores de cabecera antes de escribirlos

package handlers

import (
	"net/http"
)

// VULNERABLE (punto de inicio del ejercicio):
// func RedirectHandler(w http.ResponseWriter, r *http.Request) {
//     next := r.URL.Query().Get("next")
//     w.Header().Set("Location", next)
//     w.WriteHeader(http.StatusFound)
// }
//
// Un atacante puede enviar: next=/home%0d%0aSet-Cookie: session=attacker
// Esto inyecta una cabecera Set-Cookie fraudulenta en la respuesta.

func RedirectHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	w.Header().Set("Location", next)
	w.WriteHeader(http.StatusFound)
}

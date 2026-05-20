// src/go/handlers/middleware.go
// PASO 15: Clickjacking — middleware de cabeceras de seguridad con X-Frame-Options

package handlers

import "net/http"

// VULNERABLE (punto de inicio del ejercicio):
// func SecurityHeadersMiddleware(next http.Handler) http.Handler {
//     return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//         next.ServeHTTP(w, r)
//     })
// }
//
// Sin X-Frame-Options, un atacante puede incrustar la aplicacion en un iframe
// invisible superpuesto sobre un boton atractivo. El usuario cree hacer clic
// en "Ganar premio" pero en realidad esta haciendo clic en "Confirmar transferencia"
// (Clickjacking / UI redressing).

// SecurityHeadersMiddleware anade cabeceras de seguridad a todas las respuestas.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

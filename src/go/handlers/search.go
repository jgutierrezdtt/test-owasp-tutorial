// src/go/handlers/search.go
// PASO 13: ReDoS — regex seguro y longitud maxima de input

package handlers

import (
	"net/http"
	"regexp"
)

// VULNERABLE (punto de inicio del ejercicio):
// var emailPattern = regexp.MustCompile(`^(([a-zA-Z]+)+)@example\.com$`)
//
// func SearchHandler(w http.ResponseWriter, r *http.Request) {
//     input := r.URL.Query().Get("q")
//     if emailPattern.MatchString(input) {
//         w.Write([]byte("valid"))
//     }
// }
//
// El patron (([a-zA-Z]+)+) tiene backtracking catastrofico: para un input como
// "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX" el motor de regex explora un numero
// exponencial de combinaciones, bloqueando el servidor durante segundos o minutos.
// Esto es suficiente para un ataque de denegacion de servicio con pocas peticiones.

var emailPattern = regexp.MustCompile(`^(([a-zA-Z]+)+)@example\.com$`)

func SearchHandler(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if emailPattern.MatchString(input) {
		w.Write([]byte("valid"))
	}
}

// src/go/handlers/search.go
// PASO 13: ReDoS — regex seguro y longitud maxima de input

package handlers

import (
	"net/http"
	"regexp"
)

var safeEmailPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._%+\-]{0,63}@example\.com$`)

func SearchHandler(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("q")
	if len(input) > 200 {
		http.Error(w, "input too long", http.StatusBadRequest)
		return
	}
	if safeEmailPattern.MatchString(input) {
		w.Write([]byte("valid"))

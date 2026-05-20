// src/go/handlers/upload.go
// PASO 12: Race Condition (TOCTOU) — operacion atomica con O_EXCL elimina la ventana

package handlers

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const uploadDir = "/var/uploads"

// VULNERABLE (punto de inicio del ejercicio):
// func UploadHandler(w http.ResponseWriter, r *http.Request) {
//     filename := r.FormValue("name")
//     path := filepath.Join(uploadDir, filename)
//     if _, err := os.Stat(path); err == nil {
//         http.Error(w, "File already exists", http.StatusConflict)
//         return
//     }
//     // TOCTOU: otro goroutine/proceso puede crear el archivo entre Stat y Create
//     f, _ := os.Create(path)
//     defer f.Close()
//     io.Copy(f, r.Body)
// }
//
// En la ventana entre os.Stat y os.Create, otro proceso puede crear el archivo.
// Esto puede usarse para sobreescribir archivos existentes o provocar condiciones
// de carrera que corrompan datos.

func UploadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("name")
	path := filepath.Join(uploadDir, filename)
	if _, err := os.Stat(path); err == nil {
		http.Error(w, "File already exists", http.StatusConflict)
		return
	}
	f, _ := os.Create(path)
	defer f.Close()
	io.Copy(f, r.Body)
}

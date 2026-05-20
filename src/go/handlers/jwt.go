// src/go/handlers/jwt.go
// PASO 27: JWT Algorithm Confusion — validar explicitamente el algoritmo de firma

package handlers

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// VULNERABLE (punto de inicio del ejercicio):
// func ParseToken(tokenString string) (*jwt.MapClaims, error) {
//     token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
//         return []byte("secret"), nil
//     })
//     if err != nil || !token.Valid {
//         return nil, fmt.Errorf("invalid token")
//     }
//     claims := token.Claims.(jwt.MapClaims)
//     return &claims, nil
// }
//
// La libreria acepta el header {"alg": "none"} que indica token sin firma.
// Un atacante puede crear un token con cualquier payload y alg=none:
// Header: {"alg":"none","typ":"JWT"}
// Payload: {"sub":"admin","role":"superuser","exp":9999999999}
// Firma: (vacia)
// El servidor acepta el token como valido porque "secret" no se verifica para alg=none.

func ParseToken(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		secret := os.Getenv("JWT_SECRET")
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	claims := token.Claims.(jwt.MapClaims)
	return &claims, nil
}

// ValidateJWTHandler es el handler HTTP que usa ParseToken
func ValidateJWTHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := ParseToken(tokenString)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"valid":true,"sub":"%v"}`, (*claims)["sub"])
}

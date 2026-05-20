// src/go/handlers/orders.go
// PASO 26: IDOR / BOLA — verificar que el recurso pertenece al usuario autenticado

package handlers

import (
	"encoding/json"
	"net/http"
)

type Order struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	Total  float64 `json:"total"`
	Items  []string `json:"items"`
}

var ordersDB = []Order{
	{ID: "order-001", UserID: "user-alice", Total: 99.99, Items: []string{"laptop-stand"}},
	{ID: "order-002", UserID: "user-bob", Total: 249.50, Items: []string{"monitor", "keyboard"}},
	{ID: "order-003", UserID: "user-alice", Total: 19.99, Items: []string{"usb-cable"}},
}

func findOrderByID(id string) *Order {
	for i := range ordersDB {
		if ordersDB[i].ID == id {
			return &ordersDB[i]
		}
	}
	return nil
}

// VULNERABLE (punto de inicio del ejercicio):
// func GetOrder(w http.ResponseWriter, r *http.Request) {
//     orderID := r.URL.Query().Get("id")
//     order := findOrderByID(orderID)
//     if order == nil {
//         http.Error(w, "not found", http.StatusNotFound)
//         return
//     }
//     json.NewEncoder(w).Encode(order)
// }
//
// No se verifica que el pedido pertenezca al usuario que hace la peticion.
// Alice puede pedir order-002 (de Bob) cambiando el parametro id.
// En una API REST con miles de pedidos con IDs consecutivos, un atacante puede
// iterar de order-001 a order-9999 y descargar todos los pedidos del sistema.

func GetOrder(w http.ResponseWriter, r *http.Request) {
	orderID := r.URL.Query().Get("id")
	order := findOrderByID(orderID)
	if order == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(order)
}

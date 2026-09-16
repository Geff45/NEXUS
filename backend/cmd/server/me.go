package main

import (
	"encoding/json"
	"net/http"

	"nexus/internal/middleware"
)

func meHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)

		_, _ = w.Write(
			[]byte(`{"error":"method not allowed"}`),
		)

		return
	}

	claims, ok := middleware.UserClaims(r)

	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		_, _ = w.Write(
			[]byte(`{"error":"authentication required"}`),
		)

		return
	}

	response := map[string]any{
		"user_id":    claims.UserID,
		"username":   claims.Username,
		"email":      claims.Email,
		"is_creator": claims.IsCreator,
		"is_admin":   claims.IsAdmin,
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}

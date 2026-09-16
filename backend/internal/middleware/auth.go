package middleware

import (
	"context"
	"net/http"
	"strings"

	"nexus/internal/token"
)

type contextKey string

const userClaimsKey contextKey = "nexus_user_claims"

func Auth(tokenManager *token.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := strings.TrimSpace(r.Header.Get("Authorization"))

			if authHeader == "" {
				writeUnauthorized(w, "authorization header required")
				return
			}

			parts := strings.Fields(authHeader)

			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				writeUnauthorized(w, "invalid authorization header")
				return
			}

			tokenString := strings.TrimSpace(parts[1])

			if tokenString == "" {
				writeUnauthorized(w, "invalid authorization token")
				return
			}

			claims, err := tokenManager.Validate(tokenString)
			if err != nil {
				writeUnauthorized(w, "invalid or expired token")
				return
			}

			ctx := context.WithValue(
				r.Context(),
				userClaimsKey,
				claims,
			)

			next.ServeHTTP(
				w,
				r.WithContext(ctx),
			)
		})
	}
}

func UserClaims(r *http.Request) (*token.Claims, bool) {
	claims, ok := r.Context().Value(userClaimsKey).(*token.Claims)

	return claims, ok
}

func writeUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	_, _ = w.Write(
		[]byte(`{"error":"` + message + `"}`),
	)
}

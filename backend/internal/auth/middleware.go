package auth

import (
	"context"
	"net/http"
	"strings"

	"nexus/internal/token"
)

type contextKey string

const claimsContextKey contextKey = "nexus.jwt.claims"

func JWTMiddleware(
	tokenManager *token.Manager,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))

		if authHeader == "" {
			writeError(
				w,
				http.StatusUnauthorized,
				"authorization header is required",
			)
			return
		}

		parts := strings.Fields(authHeader)

		if len(parts) != 2 ||
			!strings.EqualFold(parts[0], "Bearer") {
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid authorization header",
			)
			return
		}

		claims, err := tokenManager.Validate(parts[1])
		if err != nil {
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid or expired token",
			)
			return
		}

		ctx := context.WithValue(
			r.Context(),
			claimsContextKey,
			claims,
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func ClaimsFromContext(
	ctx context.Context,
) (*token.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*token.Claims)
	return claims, ok
}

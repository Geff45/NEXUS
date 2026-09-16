package auth

import (
	"context"
	"net/http"
	"strings"

	"nexus/internal/sessions"
	"nexus/internal/token"
)

type contextKey string

const claimsContextKey contextKey = "nexus.jwt.claims"

func JWTMiddleware(
	tokenManager *token.Manager,
	sessionService *sessions.Service,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.TrimSpace(
			r.Header.Get("Authorization"),
		)

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

		tokenString := strings.TrimSpace(parts[1])

		claims, err := tokenManager.Validate(tokenString)
		if err != nil {
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid or expired token",
			)
			return
		}

		session, err := sessionService.GetByID(
			r.Context(),
			claims.SessionID,
		)

		if err != nil {
			writeError(
				w,
				http.StatusUnauthorized,
				"session is invalid or expired",
			)
			return
		}

		if session.UserID != claims.UserID {
			writeError(
				w,
				http.StatusUnauthorized,
				"session does not belong to user",
			)
			return
		}

		if err := sessionService.Touch(
			r.Context(),
			session.ID,
		); err != nil {
			writeError(
				w,
				http.StatusUnauthorized,
				"session is no longer valid",
			)
			return
		}

		ctx := context.WithValue(
			r.Context(),
			claimsContextKey,
			claims,
		)

		next.ServeHTTP(
			w,
			r.WithContext(ctx),
		)
	})
}

func ClaimsFromContext(
	ctx context.Context,
) (*token.Claims, bool) {
	claims, ok := ctx.Value(
		claimsContextKey,
	).(*token.Claims)

	return claims, ok
}

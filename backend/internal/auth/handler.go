package auth

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"nexus/internal/sessions"
	"nexus/internal/token"
	"nexus/internal/users"
)

type Handler struct {
	service        *users.Service
	tokenManager   *token.Manager
	sessionService *sessions.Service
}

func NewHandler(
	service *users.Service,
	tokenManager *token.Manager,
	sessionService *sessions.Service,
) *Handler {
	return &Handler{
		service:        service,
		tokenManager:   tokenManager,
		sessionService: sessionService,
	}
}

func (h *Handler) Register(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	var req RegisterRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid request body",
		)
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)

	if req.Username == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"username is required",
		)
		return
	}

	if req.Email == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"email is required",
		)
		return
	}

	if len(req.Password) < 8 {
		writeError(
			w,
			http.StatusBadRequest,
			"password must be at least 8 characters",
		)
		return
	}

	user, err := h.service.Register(
		r.Context(),
		req.Username,
		req.Email,
		req.Password,
	)

	if err != nil {
		switch {
		case errors.Is(err, users.ErrUsernameExists):
			writeError(
				w,
				http.StatusConflict,
				"username already exists",
			)

		case errors.Is(err, users.ErrEmailExists):
			writeError(
				w,
				http.StatusConflict,
				"email already exists",
			)

		default:
			writeError(
				w,
				http.StatusInternalServerError,
				"failed to create user",
			)
		}

		return
	}

	response := RegisterResponse{
		User: toUserResponse(user),
	}

	writeJSON(
		w,
		http.StatusCreated,
		response,
	)
}

func (h *Handler) Login(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	var req LoginRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid request body",
		)
		return
	}

	req.Login = strings.TrimSpace(req.Login)

	if req.Login == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"login is required",
		)
		return
	}

	if req.Password == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"password is required",
		)
		return
	}

	user, err := h.service.Authenticate(
		r.Context(),
		req.Login,
		req.Password,
	)

	if err != nil {
		switch {
		case errors.Is(err, users.ErrInvalidCredentials):
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid credentials",
			)

		case errors.Is(err, users.ErrInactiveUser):
			writeError(
				w,
				http.StatusForbidden,
				"user account is inactive",
			)

		default:
			writeError(
				w,
				http.StatusInternalServerError,
				"authentication failed",
			)
		}

		return
	}

	session, _, err := h.sessionService.Create(
		r.Context(),
		user.ID,
		r.UserAgent(),
		clientIPAddress(r),
	)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to create authentication session",
		)
		return
	}

	jwtToken, err := h.tokenManager.Generate(
		user,
		session.ID,
	)

	if err != nil {
		_ = h.sessionService.Revoke(
			r.Context(),
			session.ID,
		)

		writeError(
			w,
			http.StatusInternalServerError,
			"failed to generate authentication token",
		)
		return
	}

	response := LoginResponse{
		User:    toUserResponse(user),
		Token:   jwtToken,
		Session: session.ID,
	}

	writeJSON(
		w,
		http.StatusOK,
		response,
	)
}

func (h *Handler) Me(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	claims, ok := ClaimsFromContext(
		r.Context(),
	)

	if !ok {
		writeError(
			w,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	user, err := h.service.GetByID(
		r.Context(),
		claims.UserID,
	)

	if err != nil {
		switch {
		case errors.Is(err, users.ErrUserNotFound):
			writeError(
				w,
				http.StatusNotFound,
				"user not found",
			)

		default:
			writeError(
				w,
				http.StatusInternalServerError,
				"failed to retrieve user",
			)
		}

		return
	}

	writeJSON(
		w,
		http.StatusOK,
		toUserResponse(user),
	)
}

func (h *Handler) Logout(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	claims, ok := ClaimsFromContext(
		r.Context(),
	)

	if !ok {
		writeError(
			w,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	if err := h.sessionService.Revoke(
		r.Context(),
		claims.SessionID,
	); err != nil {
		if errors.Is(err, sessions.ErrSessionNotFound) {
			writeError(
				w,
				http.StatusUnauthorized,
				"session not found",
			)
			return
		}

		writeError(
			w,
			http.StatusInternalServerError,
			"failed to logout",
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		LogoutResponse{
			Message: "logout successful",
		},
	)
}

func (h *Handler) LogoutAll(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	claims, ok := ClaimsFromContext(
		r.Context(),
	)

	if !ok {
		writeError(
			w,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	if err := h.sessionService.RevokeAllForUser(
		r.Context(),
		claims.UserID,
	); err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to logout from all sessions",
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		LogoutResponse{
			Message: "all sessions revoked",
		},
	)
}

func writeJSON(
	w http.ResponseWriter,
	status int,
	value any,
) {
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(value)
}

func writeError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	writeJSON(
		w,
		status,
		ErrorResponse{
			Error: message,
		},
	)
}

func toUserResponse(
	user *users.User,
) UserResponse {
	return UserResponse{
		ID:            user.ID,
		Username:      user.Username,
		Email:         user.Email,
		Status:        user.Status,
		EmailVerified: user.EmailVerified,
		PhoneVerified: user.PhoneVerified,
		IsCreator:     user.IsCreator,
		IsAdmin:       user.IsAdmin,
		CreatedAt:     user.CreatedAt,
	}
}

func clientIPAddress(
	r *http.Request,
) string {
	if host, _, err := net.SplitHostPort(
		strings.TrimSpace(r.RemoteAddr),
	); err == nil {
		return host
	}

	return strings.TrimSpace(r.RemoteAddr)
}

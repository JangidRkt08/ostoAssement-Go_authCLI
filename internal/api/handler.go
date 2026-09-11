package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/JangidRkt08/go-cli-auth/internal/auth"
	"github.com/JangidRkt08/go-cli-auth/internal/session"
	"github.com/JangidRkt08/go-cli-auth/internal/user"
	"github.com/google/uuid"
)

type Handler struct {
	authService *auth.Service
	users       *user.Repository
	sessions    *session.Repository
}

func NewHandler(authService *auth.Service, users *user.Repository, sessions *session.Repository) *Handler {
	return &Handler{
		authService: authService,
		users:       users,
		sessions:    sessions,
	}
}

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type registerResponse struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type loginResponse struct {
	SessionID string `json:"session_id"`
	ExpiresAt string `json:"expires_at"`
}

type meResponse struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest

	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	req.Username = strings.TrimSpace(req.Username)

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	u, err := h.authService.Register(
		r.Context(),
		req.Username,
		req.Password,
	)
	if err != nil {
		if errors.Is(err, user.ErrUsernameExists) {
			writeError(w, http.StatusConflict, "username already exists")
			return
		}

		if errors.Is(err, auth.ErrInvalidUsername) ||
			errors.Is(err, auth.ErrInvalidPassword) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(
		w,
		http.StatusCreated,
		registerResponse{
			ID:       u.ID,
			Username: u.Username,
		},
	)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest

	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	req.Username = strings.TrimSpace(req.Username)

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	result, err := h.authService.Login(
		r.Context(),
		req.Username,
		req.Password,
	)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrAccountLocked):
			writeError(
				w,
				http.StatusTooManyRequests,
				"account is temporarily locked",
			)

		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid username or password",
			)

		default:
			writeError(
				w,
				http.StatusInternalServerError,
				"internal server error",
			)
		}

		return
	}

	writeJSON(
		w,
		http.StatusOK,
		loginResponse{
			SessionID: result.SessionID.String(),
			ExpiresAt: result.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		},
	)
}

func decodeJSON(
	w http.ResponseWriter,
	r *http.Request,
	dst any,
) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(
			w,
			http.StatusUnsupportedMediaType,
			"Content-Type must be application/json",
		)

		return errors.New("unsupported content type")
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid JSON body",
		)

		return err
	}

	if decoder.More() {
		writeError(
			w,
			http.StatusBadRequest,
			"request body must contain a single JSON object",
		)

		return errors.New("multiple JSON values")
	}

	return nil
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok {
		writeError(
			w,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	u, err := h.users.FindByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			writeError(
				w,
				http.StatusUnauthorized,
				"user not found",
			)
			return
		}

		writeError(
			w,
			http.StatusInternalServerError,
			"internal server error",
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		meResponse{
			ID:       u.ID,
			Username: u.Username,
		},
	)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
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

	sessionID, err := uuid.Parse(parts[1])
	if err != nil {
		writeError(
			w,
			http.StatusUnauthorized,
			"invalid session",
		)
		return
	}

	if err := h.sessions.Delete(
		r.Context(),
		sessionID,
	); err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"internal server error",
		)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(
	w http.ResponseWriter,
	status int,
	data any,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(data)
}

func writeError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	writeJSON(
		w,
		status,
		errorResponse{
			Error: message,
		},
	)
}

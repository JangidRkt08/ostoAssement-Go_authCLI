package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/JangidRkt08/go-cli-auth/internal/session"
	"github.com/google/uuid"
)

type contextKey string

const userIDKey contextKey = "user_id"

func WithAuthentication(
	sessionRepo *session.Repository,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			writeError(
				w,
				http.StatusUnauthorized,
				"authentication required",
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

		sessionID, err := uuid.Parse(parts[1])
		if err != nil {
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid session",
			)
			return
		}

		s, err := sessionRepo.FindByID(
			r.Context(),
			sessionID,
		)
		if err != nil {
			if errors.Is(err, session.ErrSessionNotFound) {
				writeError(
					w,
					http.StatusUnauthorized,
					"invalid session",
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

		if !s.ExpiresAt.After(time.Now().UTC()) {
			// Remove expired sessions so they cannot accumulate.
			_ = sessionRepo.Delete(r.Context(), s.ID)

			writeError(
				w,
				http.StatusUnauthorized,
				"session expired",
			)
			return
		}

		ctx := context.WithValue(
			r.Context(),
			userIDKey,
			s.UserID,
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func userIDFromContext(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(userIDKey).(int64)
	return id, ok
}

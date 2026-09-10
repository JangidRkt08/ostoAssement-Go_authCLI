package user

import "time"

type User struct {
	ID                  int64
	Username            string
	PasswordHash        string
	TOTPSecret          *string
	MFAEnabled          bool
	FailedLoginAttempts int
	LockedUntil         *time.Time
	CreatedAt           time.Time
	LastLoginAt         *time.Time
}

# Go CLI Auth

A containerized Go command-line authentication system with PostgreSQL persistence, secure password hashing, session management, account lockout, and optional TOTP-based 2FA.

## Objective

This project implements a secure interactive CLI authentication system with:

- User registration and username/password login
- bcrypt password hashing
- Optional TOTP-based two-factor authentication
- Google Authenticator-compatible TOTP
- Configurable session expiration
- Account lockout after repeated failed logins
- PostgreSQL persistence
- REST API with Bearer-token session authentication
- Interactive CLI with command history and tab completion
- Docker and Docker Compose support

## Features

- User registration
- Username/password authentication
- bcrypt password hashing
- Optional TOTP-based 2FA
- Google Authenticator-compatible TOTP
- Session management with configurable timeout
- Account lockout after failed login attempts
- Interactive CLI
- Command history and tab completion
- PostgreSQL persistence
- REST API protected by Bearer sessions
- Database migrations
- Unit tests for core authentication and security logic

## Security Features

- Passwords are securely hashed using bcrypt.
- Session-based authentication using Bearer tokens.
- Configurable session expiration.
- Optional TOTP-based two-factor authentication.
- Account lockout after repeated failed login attempts.
- Configurable maximum login attempts and lockout duration.
- Failed login attempts are reset after a successful authentication.
- Protected API endpoints require a valid session.

### Account Lockout

The application protects against repeated password guessing attempts.

By default, after 5 consecutive failed login attempts, the account is temporarily locked for 15 minutes.

Example:

```text
Attempt 1 → invalid username or password
Attempt 2 → invalid username or password
Attempt 3 → invalid username or password
Attempt 4 → invalid username or password
Attempt 5 → invalid username or password

Correct password while locked:
→ HTTP 429
→ {"error":"account is temporarily locked"}


```

## Tech Stack

- **Go**
- **PostgreSQL**
- **Docker / Docker Compose**
- **HTTP REST API**
- **bcrypt**
- **TOTP / OTP**
- **readline** for the interactive CLI

## Project Structure

```text
.
├── cmd/
│   └── app/
│       └── main.go
├── internal/
│   ├── api/             # HTTP handlers and authentication middleware
│   ├── auth/            # Authentication business logic
│   ├── cli/             # Interactive CLI and API client
│   ├── database/        # PostgreSQL connection
│   ├── security/        # Password hashing and verification
│   ├── session/         # Session repository
│   └── user/            # User model and repository
├── migrations/           # Database schema migrations
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── go.mod
└── go.sum
```

## Requirements

- Go 1.26+
- Docker
- Docker Compose

## Configuration

Create a `.env` file from `.env.example`:

```bash
cp .env.example .env
```

Example configuration:

```env
POSTGRES_USER=auth_user
POSTGRES_PASSWORD=auth_password
POSTGRES_DB=auth_db

# When the Go application runs directly on the host:
DATABASE_URL=postgres://auth_user:auth_password@localhost:5433/auth_db?sslmode=disable

SESSION_TIMEOUT=30m
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=15m
```

> **Docker note:** When the application runs inside the same Docker network as PostgreSQL, use the PostgreSQL service name and internal port:
>
> `postgres://auth_user:auth_password@postgres:5432/auth_db?sslmode=disable`

## Running with Docker Compose

Start PostgreSQL:

```bash
docker compose up -d
```

Check that the database is healthy:

```bash
docker compose ps
```

The PostgreSQL container persists its data using a named Docker volume.

## Running the Application

### Option 1: Run the Go application directly

Make sure PostgreSQL is running:

```bash
docker compose up -d
```

Then:

```bash
go run ./cmd/app
```

### Option 2: Build and run the application container

Build:

```bash
docker build -t go-cli-auth .
```

Run the application on the same Docker network as PostgreSQL:

```bash
docker run --rm -it \
  --network go-cli-auth_default \
  -p 8080:8080 \
  -e DATABASE_URL="postgres://auth_user:auth_password@postgres:5432/auth_db?sslmode=disable" \
  go-cli-auth
```

## CLI Usage

After starting the application:

```text
Go CLI Auth
Type 'help' for available commands.

auth>
```

### Available Commands

#### Before Login

```text
register       Create a new account
login          Login to your account
help            Show available commands
exit            Exit the application
```

#### After Login

```text
whoami         Show current user
enable-2fa     Enable TOTP-based MFA
disable-2fa    Disable MFA
logout         Logout
help            Show available commands
```

### Register

```text
auth> register
Username: testuser
Password: ********
Account created successfully.
```

### Login

```text
auth> login
Username: testuser
Password: ********
TOTP code (press Enter if disabled):
Login successful.
Session expires at: ...
```

If MFA is enabled, a valid six-digit TOTP code is required.

### Enable 2FA

After logging in:

```text
auth> enable-2fa
```

The application generates a TOTP secret and authenticator URL. Add the secret to an authenticator application such as Google Authenticator, then verify the generated six-digit code.

A successful setup reports:

```text
Two-factor authentication enabled successfully.
```

After logging out, login requires the TOTP code.

### Disable 2FA

While authenticated:

```text
auth> disable-2fa
```

### Check Current User

```text
auth> whoami
ID: 1
Username: testuser
```

### Logout

```text
auth> logout
Logged out successfully.
```

After logout, authenticated commands fail until another login is performed.

## REST API

The CLI communicates with the Go HTTP API.

Base URL:

```text
http://localhost:8080/api/v1
```

### Register

```bash
curl -i \
  -X POST \
  http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"api_test","password":"StrongPassword123!"}'
```

### Login

Without MFA:

```bash
curl -i \
  -X POST \
  http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"api_test","password":"StrongPassword123!"}'
```

With MFA:

```bash
curl -i \
  -X POST \
  http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"api_test","password":"StrongPassword123!","totp_code":"123456"}'
```

A successful login returns a session ID and expiration time.

### Get Current User

```bash
curl -i \
  http://localhost:8080/api/v1/me \
  -H "Authorization: Bearer <SESSION_ID>"
```

Without authentication the API returns:

```text
401 Unauthorized
```

### Logout

```bash
curl -i \
  -X POST \
  http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer <SESSION_ID>"
```

## Authentication and Security

### Password Storage

Passwords are never stored as plaintext. They are hashed using bcrypt before being persisted.

### Account Lockout

Repeated failed login attempts are tracked. Once the configured maximum number of attempts is reached, the account is temporarily locked for the configured lockout duration.

Configuration:

```env
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=15m
```

### Sessions

Successful authentication creates a server-side session. The client uses the session ID as a Bearer token:

```text
Authorization: Bearer <SESSION_ID>
```

Session expiration is configurable:

```env
SESSION_TIMEOUT=30m
```

### TOTP 2FA

MFA is optional. When enabled, successful password authentication also requires a valid time-based one-time password.

If MFA is enabled and no code is supplied, the API returns:

```json
{"error":"MFA code required"}
```

## Database

PostgreSQL runs in Docker and uses a named volume for persistence:

```yaml
volumes:
  postgres_data:
```

Database schema is maintained through SQL migrations in:

```text
migrations/
```

The project uses PostgreSQL rather than SQLite/MySQL for persistent authentication and session data.

## Testing

Run all Go tests:

```bash
go test ./...
```

Run with the race detector:

```bash
go test -race ./...
```

The test suite includes core authentication and password-security tests.

## Docker Build Verification

Build the image:

```bash
docker build -t go-cli-auth .
```

The image uses a multi-stage build:

1. Go builder image compiles the application.
2. A smaller Alpine image runs the resulting binary.

## Design

The application is separated into layers:

- **CLI** — user interaction and API client
- **API** — HTTP handlers and authentication middleware
- **Auth service** — authentication business rules
- **Repositories** — database access
- **Security** — password hashing/verification
- **Session** — server-side session management
- **Database** — PostgreSQL connection and persistence

This separation keeps HTTP, CLI, business logic, and persistence concerns independent and easier to test.

## Error Handling

The API returns appropriate HTTP status codes for common authentication failures, including:

- `400 Bad Request` — invalid/missing input
- `401 Unauthorized` — invalid credentials, missing/invalid MFA, or authentication required
- `409 Conflict` — username already exists
- `429 Too Many Requests` — account temporarily locked
- `500 Internal Server Error` — unexpected server-side failure

The CLI converts API errors into readable messages for interactive use.

## Submission Checklist

- [x] Go source code
- [x] PostgreSQL persistence
- [x] Dockerfile
- [x] Docker Compose configuration
- [x] Database migrations
- [x] Interactive CLI
- [x] History and tab completion
- [x] Registration
- [x] Password authentication
- [x] bcrypt password hashing
- [x] Session management
- [x] Account lockout
- [x] Optional TOTP 2FA
- [x] REST API
- [x] Authentication middleware
- [x] Core unit tests
- [x] README with setup and usage instructions

## License

This project was created as a backend engineering assessment project.

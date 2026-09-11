FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o go-cli-auth ./cmd/app

FROM alpine:3.21

WORKDIR /app

COPY --from=builder /app/go-cli-auth .

EXPOSE 8080

CMD ["./go-cli-auth"]

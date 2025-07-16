FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY . .

# Build the admission controller
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o webhook ./cmd/admission

FROM alpine:latest

WORKDIR /
COPY --from=builder /app/webhook /webhook

ENTRYPOINT ["/webhook"] 
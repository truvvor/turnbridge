# Build stage
FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /out/captcha-service .

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S app && adduser -S app -G app && \
    mkdir -p /var/trap && chown app:app /var/trap

USER app
WORKDIR /app
COPY --from=build /out/captcha-service /app/captcha-service

ENV LISTEN_ADDR=:8080
ENV CAPTCHA_TRAP_DIR=/var/trap

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/app/captcha-service"]

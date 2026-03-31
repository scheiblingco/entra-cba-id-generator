FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o entra-cba-id-generator .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/entra-cba-id-generator .

VOLUME ["/app/.acme"]

EXPOSE 8559

ENTRYPOINT ["./entra-cba-id-generator"]

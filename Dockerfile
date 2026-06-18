FROM golang:1.26-bookworm AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go env -w GOPROXY=https://goproxy.cn,direct && \
    go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o headscale ./cmd/headscale

FROM gcr.io/distroless/base-debian13
COPY --from=builder /app/headscale /usr/local/bin/headscale
ENTRYPOINT ["/usr/local/bin/headscale"]
CMD ["serve"]

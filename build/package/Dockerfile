# Build go
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

WORKDIR /app
# Cache dependencies independently of application source changes.
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

ENV CGO_ENABLED=0
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -v -o vless-node -trimpath -ldflags "-s -w -X main.Version=${VERSION}" ./cmd/server

# Release
FROM alpine:3.23
# Install dependencies
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

COPY --from=builder /app/vless-node /usr/local/bin

ENTRYPOINT ["vless-node"]

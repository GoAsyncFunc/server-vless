# Build go
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

WORKDIR /app
COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

ENV CGO_ENABLED=0
RUN go mod download
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -v -o vless-node -trimpath -ldflags "-s -w -X main.Version=${VERSION}" ./cmd/server

# Release
FROM alpine
# Install dependencies
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

COPY --from=builder /app/vless-node /usr/local/bin
ENTRYPOINT ["vless-node"]

# Build go
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

WORKDIR /app

# Fetch the geo data before the source copy so a code change does not
# re-download ~28 MB. geoip.dat is required at runtime: the direct egress
# resolves its geoip:private rule by opening the file while building the
# outbound. The script verifies both files against pinned sha256 values.
COPY build/package/fetch-geo-assets.sh /usr/local/bin/fetch-geo-assets.sh
RUN fetch-geo-assets.sh /usr/local/share/xray

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
# /usr/local/share/xray is one of the directories Xray searches for geo data.
COPY --from=builder /usr/local/share/xray /usr/local/share/xray

ENTRYPOINT ["vless-node"]

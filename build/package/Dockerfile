# Build go
# Base images are pinned by digest as well as tag: the tag is mutable, and this
# stage ends up inside every published image.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder

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
FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
# Install dependencies
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

COPY --from=builder /app/vless-node /usr/local/bin
# /usr/local/share/xray is one of the directories Xray searches for geo data.
COPY --from=builder /usr/local/share/xray /usr/local/share/xray

# Run unprivileged. The one privileged thing a VLESS node does is bind its port,
# which is usually 443, so grant that capability to the binary rather than
# keeping the container as root. Docker's default bounding set contains
# NET_BIND_SERVICE, and that is what lets a file capability take effect for a
# non-root user. libcap is only needed to set it.
RUN apk --no-cache add libcap \
    && setcap cap_net_bind_service=+ep /usr/local/bin/vless-node \
    && adduser -D -H -u 10001 vless \
    && apk del libcap
USER 10001:10001

ENTRYPOINT ["vless-node"]

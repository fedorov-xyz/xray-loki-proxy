FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.25 AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0
ENV GO111MODULE=on

WORKDIR /builder

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download

COPY . .

RUN CGO_ENABLED=${CGO_ENABLED} GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -a -installsuffix cgo -o /usr/bin/xray-loki-proxy .

# Temporary debug base (shell/ping). Revert to gcr.io/distroless/static for prod.
FROM --platform=${BUILDPLATFORM:-linux/amd64} alpine:3.21

RUN apk add --no-cache curl bind-tools iputils

WORKDIR /app
COPY --from=builder /usr/bin/xray-loki-proxy /

ENTRYPOINT ["/xray-loki-proxy"]

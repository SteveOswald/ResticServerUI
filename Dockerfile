# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go vet ./... && go test ./...
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/restic-server-ui .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/restic-server-ui /restic-server-ui
ENV CONFIG_DIR=/config \
    DATA_DIR=/data \
    UI_LISTEN=:8080 \
    GATEWAY_LISTEN=:8000 \
    UI_TLS_LISTEN=:8443 \
    GATEWAY_TLS_LISTEN=:8444
EXPOSE 8000 8080 8443 8444
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/restic-server-ui", "healthcheck"]
ENTRYPOINT ["/restic-server-ui"]

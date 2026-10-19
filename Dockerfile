# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine AS build
ARG TARGETARCH
WORKDIR /src
RUN test "$TARGETARCH" = amd64 || (echo 'Only linux/amd64 images are supported' >&2; exit 1)
COPY go.mod go.sum ./
# Keep modules in an exported layer: GitHub's layer cache does not export cache mounts.
RUN go mod download
COPY *.go ./
COPY cmd/dns-guard ./cmd/dns-guard
RUN --mount=type=cache,id=guard-backend-go-build,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -buildvcs=false -trimpath -ldflags='-s -w -buildid=' -o /out/dns-guard ./cmd/dns-guard \
    && mkdir -p /out/data /out/tmp \
    && chown 10001:10001 /out/data \
    && chmod 700 /out/data \
    && chmod 1777 /out/tmp

FROM scratch
COPY --link --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --link --from=build --chown=10001:10001 --chmod=0700 /out/data /data
COPY --link --from=build --chmod=1777 /out/tmp /tmp
# The binary changes most often; stable runtime files remain independent layers.
COPY --link --from=build /out/dns-guard /dns-guard
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/dns-guard", "--healthcheck"]
ENTRYPOINT ["/dns-guard"]

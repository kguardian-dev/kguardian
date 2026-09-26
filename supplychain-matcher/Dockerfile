# Cross-compile on the build platform: static Go (CGO off; the Grype DB is
# read with a pure-Go SQLite driver), so arm64 needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY internal ./internal

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/kguardian-supplychain-matcher .

# Distroless static, nonroot (uid/gid 65532): no shell. Probes use the
# binary's own "probe" subcommand because the server is loopback-only.
FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=builder /out/kguardian-supplychain-matcher /usr/local/bin/kguardian-supplychain-matcher

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/kguardian-supplychain-matcher"]
CMD ["serve"]

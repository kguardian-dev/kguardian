# Cross-compile on the build platform: static Go (CGO off; the rpm
# database is read with a pure-Go SQLite driver), so arm64 needs no
# emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY internal ./internal

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
# CGO off also matters at runtime: the worker applies capability, nice and
# I/O-priority changes to every thread with AllThreadsSyscall, which needs
# a cgo-free binary.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/kguardian-cataloger .

# Distroless static: no shell, no package manager.
#
# The image defaults to the nonroot user (65532). Run that way, the worker
# can neither change uid nor hold CAP_DAC_READ_SEARCH, so it falls back to
# capability model (ii) (unreadable files counted, completeness partial).
# The chart runs it as uid 0 with every capability dropped except
# DAC_READ_SEARCH, SETUID and SETGID (model (i)): the uid-0 parent parses
# nothing and starts every scan as uid 2000000000 with DAC_READ_SEARCH as
# its only capability (README "Process model").
FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=builder /out/kguardian-cataloger /usr/local/bin/kguardian-cataloger

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/kguardian-cataloger"]
CMD ["serve"]

# Cross-compile on the build platform: the binary is static Go (CGO off),
# so arm64 needs no emulation and the runtime stage has no RUN steps.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
COPY pkg ./pkg

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/kguardian-supplychain .

# Distroless static, nonroot (uid/gid 65532): no shell, no package manager.
FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=builder /out/kguardian-supplychain /usr/local/bin/kguardian-supplychain

USER 65532:65532

EXPOSE 8083

ENTRYPOINT ["/usr/local/bin/kguardian-supplychain"]
CMD ["serve"]

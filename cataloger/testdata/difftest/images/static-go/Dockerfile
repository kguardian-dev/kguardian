# A static Go binary (CGO off) with one module dependency, on scratch:
# Syft finds it only through the Go build info in the binary.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY main.go ./
RUN go mod init example.com/hello \
 && go get golang.org/x/text@v0.30.0 \
 && CGO_ENABLED=0 go build -trimpath -o /hello .

FROM scratch
COPY --from=build /hello /usr/local/bin/hello
# A test fixture that is only ever unpacked, never run: no health check,
# and a non-root user (neither changes what the differential test sees).
USER 65532:65532
HEALTHCHECK NONE
ENTRYPOINT ["/usr/local/bin/hello"]

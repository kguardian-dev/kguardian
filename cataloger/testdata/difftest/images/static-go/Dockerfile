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
ENTRYPOINT ["/usr/local/bin/hello"]

FROM golang:1.22.3-alpine3.18 as build

# Buildx build-in ARGs
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT=""
# Additional build ARGs passed from --build-args
ARG APPLICATION_NAME="advisor"
ARG VERSION
ARG SHA

# Environment variables used at compile time by Golang
ENV GO111MODULE=on \
  CGO_ENABLED=0 \
  GOOS=${TARGETOS} \
  GOARCH=${TARGETARCH} \
  GOARM=${TARGETVARIANT}

WORKDIR /go/src/github.com/kguardian-dev/kguardian/advisor/

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -a -installsuffix cgo \
  -ldflags="-w -extldflags '-static' \
  -X 'main.ApplicationName=${APPLICATION_NAME}}' \
  -X 'main.Version=${VERSION}' -X 'main.SHA=${SHA}' \
  -X 'github.com/kguardian-dev/kguardian/advisor/pkg/k8s.Version=${VERSION}'" \
  -o advisor .

FROM gcr.io/distroless/static:nonroot

ARG LOG_INFO
ARG PORT

ENV LOG_INFO=${LOG_INFO} \
  PORT=${PORT}

WORKDIR /

COPY --from=build --chown=nonroot /go/src/github.com/kguardian-dev/kguardian/advisor/advisor .

USER nonroot:nonroot

ENTRYPOINT ["/advisor"]

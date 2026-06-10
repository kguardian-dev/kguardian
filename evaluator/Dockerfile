FROM golang:1.26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY pkg ./pkg

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o kguardian-evaluator .

FROM alpine:3.24

WORKDIR /app

RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 -g 1000 evaluator

COPY --from=builder /app/kguardian-evaluator /usr/local/bin/kguardian-evaluator

USER 1000:1000

EXPOSE 8082

ENTRYPOINT ["/usr/local/bin/kguardian-evaluator"]

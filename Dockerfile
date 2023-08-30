FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY . .

RUN go build -o /go/bin/securityscanner cmd/main/main.go

FROM alpine:latest

RUN apk add --no-cache wget ca-certificates

RUN wget  https://github.com/aquasecurity/trivy/releases/download/v0.44.0/trivy_0.44.0_Linux-64bit.tar.gz && \
    tar zxvf trivy_0.44.0_Linux-64bit.tar.gz && \
    mv trivy /usr/local/bin && \
    rm -f trivy_0.44.0_Linux-64bit.tar.gz

COPY --from=builder /go/bin/securityscanner /go/bin/securityscanner

CMD ["/go/bin/securityscanner"]
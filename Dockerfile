# Basic go installation with dep
FROM golang:1.11.1-alpine as go-env

RUN apk update && apk add curl git
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
WORKDIR /go/src/github.com/kekru/forward-proxy-auth/
RUN ln -s /go/src/github.com/kekru/forward-proxy-auth/ /fpa

# Build the go binary
FROM go-env AS builder
ARG RUN_ENSURE=1
ADD . .
RUN if [ $RUN_ENSURE -eq 1 ]; then dep ensure; fi
RUN dep check
RUN CGO_ENABLED=0 GOOS=linux go build -a -o forward-proxy-auth .

# Fetch default TLS certificates
FROM alpine:3.6 as certificatefetcher
RUN apk add -U --no-cache ca-certificates

# Target image with the go binary, config files and TLS certificates
FROM scratch

ARG SOURCE_COMMIT
ARG SOURCE_TAG
ARG BUILD_DATE
LABEL org.label-schema.build-date=$BUILD_DATE \
	org.label-schema.name="kekru forward-proxy-auth" \
	org.label-schema.description="forward authentication service for use with traefik" \
    org.label-schema.vendor="Kevin Krummenauer" \
	org.label-schema.url="https://github.com/kekru/forward-proxy-auth" \
	org.label-schema.vcs-ref=$SOURCE_COMMIT \
	org.label-schema.vcs-url="https://github.com/kekru/forward-proxy-auth" \
    org.label-schema.usage="https://github.com/kekru/forward-proxy-auth" \
	org.label-schema.version=$SOURCE_TAG \
	org.label-schema.schema-version="1.0"

WORKDIR /
COPY --from=builder /go/src/github.com/kekru/forward-proxy-auth/forward-proxy-auth /
COPY --from=certificatefetcher /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY config.yml /config.yml
COPY static /static
CMD ["/forward-proxy-auth"]

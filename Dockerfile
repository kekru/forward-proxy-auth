FROM golang:1.11.1-alpine as builder

RUN apk update && apk add curl git
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
WORKDIR /go/src/github.com/kekru/forward-proxy-auth/
ADD . .
RUN dep ensure
RUN CGO_ENABLED=0 GOOS=linux go build -a -o forward-proxy-auth .

FROM scratch
WORKDIR /
COPY --from=builder /go/src/github.com/kekru/forward-proxy-auth/forward-proxy-auth /
COPY config.yml /config.yml
CMD ["/forward-proxy-auth"] 
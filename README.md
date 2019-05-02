[![Build Status](https://travis-ci.org/kekru/forward-proxy-auth.svg?branch=master)](https://travis-ci.org/kekru/forward-proxy-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/kekru/forward-proxy-auth)](https://goreportcard.com/report/github.com/kekru/forward-proxy-auth)
[![Microbadger Layers](https://images.microbadger.com/badges/image/whiledo/forward-proxy-auth.svg)](https://microbadger.com/images/whiledo/forward-proxy-auth "Get your own image badge on microbadger.com")

# forward-proxy-auth
This aims to be a forward auth service usable by traefik's forward authentication.  
This is still work in progress and it is my first project in golang.

## simple all in one service
+ user authentication against LDAP and plain text file
+ create JWTs, storing in cookies
+ explicitly no OAuth/OpenId connect workflow, no large configuration of authentication providers  
  (Update: OpenId Connect Support in Branch `oidc`)
+ aims to be a simple and only basic SSO solution for small Docker Swarm clusters

# Usage examples

See [integrationtest/resources/compose](integrationtest/resources/compose) for usage examples.


# Build and run
Run in docker:  
```bash
docker build -t forward-proxy-auth .
docker run --rm -it -p 8080:8080 forward-proxy-auth
```

Faster docker build, if go dependencies are already fetched (if "dep ensure" has already been run)  
```bash
docker build -t forward-proxy-auth --build-arg=RUN_ENSURE=0 .
```

# Dockerized development environment
If you don't have go installed locally, you can create a basic dockerized development environment.  

```bash
# First build the image (builds only the "go-env" part of the Dockerfile)
docker build --target go-env -t go-env .
# Then run a terminal session in the container, with the mounted workspace ...
docker run --rm -it -v $(pwd):/fpa go-env
# ... or run "dep ensure" directly ...
docker run --rm -it -v $(pwd):/fpa go-env dep ensure
# ... or create the binary
docker run --rm -it -v $(pwd):/fpa go-env go build
```

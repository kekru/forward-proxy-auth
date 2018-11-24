[![Build Status](https://travis-ci.org/kekru/forward-proxy-auth.svg?branch=master)](https://travis-ci.org/kekru/forward-proxy-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/kekru/forward-proxy-auth)](https://goreportcard.com/report/github.com/kekru/forward-proxy-auth)

# forward-proxy-auth
This aims to be a forward auth service usable by traefik's forward authentication.  
This is still work in progress and it is my first project in golang.

## simple all in one service
+ user authentication against LDAP and plain text file
+ create JWTs, storing in cookies
+ explicitly no OAuth/OpenId connect workflow, no large configuration of authentication providers 
+ aims to be a simple and only basic SSO solution for small Docker Swarm clusters


# Build and run
Run in docker:  
```bash
docker build -t forward-proxy-auth --build-arg=RUN_ENSURE=1 .
docker run --rm -it -p 8080:8080 forward-proxy-auth
```

package main

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
)

type JwtUtil struct {
	ExpireSeconds  int
	HmacSigningKey []byte
	Issuer         string
}

type ForwardProxyClaims struct {
	*User
	jwt.StandardClaims
}

func (jwtUtil *JwtUtil) validateToken(tokenString string) (user *User, expiryTime time.Time, err error) {

	token, err := jwt.ParseWithClaims(tokenString, &ForwardProxyClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtUtil.HmacSigningKey, nil
	})

	if claims, ok := token.Claims.(*ForwardProxyClaims); ok && token.Valid {
		return claims.User, time.Unix(claims.StandardClaims.ExpiresAt, 0).UTC(), nil
	}

	return nil, time.Time{}, err
}

func (jwtUtil *JwtUtil) createToken(user *User) (tokenString string, expiryTime time.Time, err error) {

	expiryTime = time.Now().UTC().Add(time.Second * time.Duration(jwtUtil.ExpireSeconds))

	claims := ForwardProxyClaims{
		user,
		jwt.StandardClaims{
			ExpiresAt: expiryTime.Unix(),
			Issuer:    jwtUtil.Issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(jwtUtil.HmacSigningKey)
	log.Debugf("Created token for user %s", user.Name)
	return
}

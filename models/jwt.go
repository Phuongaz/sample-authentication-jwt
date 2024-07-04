package models

import "github.com/dgrijalva/jwt-go"

type JWTClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

func (u *JWTClaims) IsAdmin() bool {
	return u.Role == "admin"
}

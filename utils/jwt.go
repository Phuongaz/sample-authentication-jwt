package utils

import (
	"encoding/gob"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"authentication/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte

var Store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET_KEY")))

func init() {
	Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	gob.Register(&models.User{})

	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
}

func GetJWTSecret() string {
	return string(jwtSecret)
}

func GenerateJWT(username, role string) (string, error) {
	expirationTime := time.Now().Add(30 * time.Second)

	claims := &models.JWTClaims{
		Username: username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func GenerateRefreshToken(username, role string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)

	claims := &models.JWTClaims{
		Username: username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateUser(username, password string) (*models.User, error) {
	var user models.User
	user.Username = username

	query := "SELECT id, password, role FROM users WHERE username=?"

	err := db.QueryRow(query, username).Scan(&user.ID, &user.Password, &user.Role)

	if err != nil {
		return nil, err
	}
	isCompare := ComparePasswords(user.Password, password)
	if !isCompare {
		return nil, errors.New("Username or password is incorrect")
	}

	return &user, nil
}

func ValidateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func HashPassword(password string) string {
	byte, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
	}
	return string(byte)
}

func ComparePasswords(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

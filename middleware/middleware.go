package middleware

import (
	"fmt"
	"log"
	"net/http"

	"authentication/models"
	"authentication/utils"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
)

func AdminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractToken(r)
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &models.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(utils.GetJWTSecret()), nil
		})

		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(*models.JWTClaims); ok && token.Valid {
			if !claims.IsAdmin() {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			fmt.Printf("Authenticated user: %s\n", claims.Username)
			context.Set(r, "user", claims.Username)
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	})
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractToken(r)
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &models.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(utils.GetJWTSecret()), nil
		})

		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(*models.JWTClaims); ok && token.Valid {
			fmt.Printf("Authenticated user: %s\n", claims.Username)
			context.Set(r, "user", claims.Username)
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	})
}

func LogoutMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := utils.Store.Get(r, "auth-session")
		session.Values["authenticated"] = false
		delete(session.Values, "user")
		session.Options.MaxAge = -1
		err := session.Save(r, w)
		if err != nil {
			fmt.Println("Error saving session: ", err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func LoginMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := utils.Store.Get(r, "auth-session")
		_, ok := session.Values["user"]
		log.Println("Logging out")
		fmt.Println(session.Values["authenticated"])
		fmt.Println(session.Values["user"])
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func DisableCachingAndSniffing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate;")
		w.Header().Set("pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && bearerToken[:7] == "Bearer " {
		return bearerToken[7:]
	}
	return ""
}

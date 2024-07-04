package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"authentication/models"
	"authentication/utils"
)

func Users(w http.ResponseWriter, r *http.Request) {
	users, err := utils.Users()
	if err != nil {
		http.Error(w, "Error getting users", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(users)
}

func Register(w http.ResponseWriter, r *http.Request) {
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	fmt.Println(user.Username, user.Password, user.Email)

	if user.Username == "" || user.Password == "" || user.Email == "" {
		http.Error(w, "Please provide username, password, and email", http.StatusBadRequest)
		return
	}

	exists, err := utils.UserExists(user.Username, user.Email)
	if err != nil {
		http.Error(w, "Error checking user existence", http.StatusInternalServerError)
		return
	}
	if exists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
		return
	}

	err = utils.CreateUser(&user)
	if err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

func Login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	validUser, err := utils.ValidateUser(user.Username, user.Password)
	if err != nil {
		http.Error(w, "Username or password is incorrect", http.StatusBadRequest)
		return
	}

	tokenString, err := utils.GenerateJWT(validUser.Username, validUser.Role)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := utils.GenerateRefreshToken(validUser.Username, validUser.Role)
	if err != nil {
		http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
		return
	}

	session, _ := utils.Store.Get(r, "auth-session")
	session.Values["authenticated"] = true
	session.Values["refresh_token"] = refreshToken
	session.Values["user"] = validUser
	err = session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session %v", err.Error())
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Authorization", "Bearer "+tokenString)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	session, _ := utils.Store.Get(r, "auth-session")
	refreshToken, ok := session.Values["refresh_token"].(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token, err := utils.ValidateToken(refreshToken)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*models.JWTClaims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	newToken, err := utils.GenerateJWT(claims.Username, claims.Role)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Authorization", "Bearer "+newToken)
	json.NewEncoder(w).Encode(map[string]string{"token": newToken})
}

func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Protected endpoint")
}

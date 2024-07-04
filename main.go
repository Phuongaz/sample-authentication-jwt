package main

import (
	"log"
	"net/http"
	"os"

	"authentication/handlers"
	"authentication/middleware"
	"authentication/utils"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	utils.InitDB()
}

func main() {
	router := mux.NewRouter()

	router.Use(middleware.DisableCachingAndSniffing)

	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	})

	router.HandleFunc("/home", middleware.LoginMiddleware(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Home endpoint")
		http.ServeFile(w, r, "./static/home.html")
	})).Methods("GET")

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/login.html")
	}).Methods("GET")

	router.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/register.html")
	}).Methods("GET")

	router.HandleFunc("/protected", middleware.AuthMiddleware(handlers.ProtectedEndpoint)).Methods("GET")

	router.HandleFunc("/logout", middleware.LogoutMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})).Methods("GET")

	router.HandleFunc("/api/register", handlers.Register).Methods("POST")
	router.HandleFunc("/api/login", handlers.Login).Methods("POST")
	router.Handle("/api/users", middleware.AdminAuthMiddleware(handlers.Users)).Methods("GET")
	router.HandleFunc("/api/refresh", handlers.RefreshToken).Methods("POST")

	log.Println("Server running on port " + os.Getenv("SERVE_PORT") + "...")
	log.Fatal(http.ListenAndServe(":"+os.Getenv("SERVE_PORT"), router))
}

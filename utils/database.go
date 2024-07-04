package utils

import (
	"authentication/models"
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func InitDB() {
	dbUsername := os.Getenv("DB_USERNAME")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")

	dbURI := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUsername, dbPassword, dbHost, dbPort, dbName)
	conn, err := sql.Open("mysql", dbURI)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	db = conn
}

func CreateUser(user *models.User) error {
	query := "INSERT INTO users (username, password, email) VALUES (?, ?, ?)"
	hashPasswod := HashPassword(user.Password)
	_, err := db.Exec(query, user.Username, hashPasswod, user.Email)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		return err
	}
	return nil
}

func Users() ([]models.User, error) {
	var users []models.User
	query := "SELECT * FROM users"
	rows, err := db.Query(query)
	if err != nil {
		log.Printf("Error getting users: %v", err)
		return nil, err
	}

	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.Role, &user.Email, &user.CreatedAt)
		if err != nil {
			log.Printf("Error scanning users: %v", err)
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func UserExists(username, email string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM users WHERE username=? OR email=?"
	err := db.QueryRow(query, username, email).Scan(&count)
	if err != nil {
		log.Printf("Error checking user existence: %v", err)
		return false, err
	}
	return count > 0, nil
}

func GetDB() *sql.DB {
	return db
}

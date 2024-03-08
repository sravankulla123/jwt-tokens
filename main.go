package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var secretKey = []byte("your-secret-key")
var refreshTokens = make(map[string]bool)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func generateAccessToken(user User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(time.Minute * 15).Unix(),
	})

	return token.SignedString(secretKey)
}

func generateRefreshToken() string {
	refreshToken := fmt.Sprintf("refresh_token_%d", time.Now().UnixNano())
	refreshTokens[refreshToken] = true
	return refreshToken
}

func validateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("error extracting claims")
	}

	return claims, nil
}

func main() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {

		user := User{
			ID:       1,
			Username: "exampleUser",
			Role:     "admin",
		}

		accessToken, err := generateAccessToken(user)
		if err != nil {
			http.Error(w, "Error generating access token", http.StatusInternalServerError)
			return
		}

		refreshToken := generateRefreshToken()

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token": "%s", "refresh_token": "%s"}`, accessToken, refreshToken)
	})

	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {

		accessToken := r.Header.Get("Authorization")
		if accessToken == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := validateToken(accessToken)
		if err != nil {
			http.Error(w, "Invalid access token", http.StatusUnauthorized)
			return
		}

		username, ok := claims["username"].(string)
		if !ok || username != "exampleUser" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Write([]byte("Protected resource accessed successfully"))
	})

	http.ListenAndServe(":8080", nil)
}

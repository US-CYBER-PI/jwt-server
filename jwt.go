package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	as "github.com/aerospike/aerospike-client-go"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	hmacSecret    = []byte("c4bd7d88edb4fa1817abb11707958924384f7933e5facfd707dc1d1429af9936")
	port          = 9096
	namespace     = "test"
	setName       = "jwt"
	aerospikeHost = "127.0.0.1"
	aerospikePort = 3000
	client        = &as.Client{}
)

func init() {

	err := godotenv.Load(".env")

	if err != nil {
		log.Println("Error loading .env file")
	}

	if os.Getenv("HMAC_SECRET") != "" {
		hmacSecret = []byte(os.Getenv("HMAC_SECRET"))
	}

	if os.Getenv("PORT") != "" {
		port, _ = strconv.Atoi(os.Getenv("PORT"))
	}

	if os.Getenv("AEROSPIKE_NAME_SPACE") != "" {
		namespace = os.Getenv("AEROSPIKE_NAME_SPACE")
	}

	if os.Getenv("AEROSPIKE_SET_NAME") != "" {
		setName = os.Getenv("AEROSPIKE_SET_NAME")
	}

	if os.Getenv("AEROSPIKE_HOST") != "" {
		aerospikeHost = os.Getenv("AEROSPIKE_HOST")
	}

	if os.Getenv("AEROSPIKE_PORT") != "" {
		aerospikePort, _ = strconv.Atoi(os.Getenv("AEROSPIKE_PORT"))
	}

}

func main() {

	var err error

	client, err = as.NewClient(aerospikeHost, aerospikePort)

	if err != nil {
		panic(err)
	}

	http.HandleFunc("/auth/token", tokenHandler)
	http.HandleFunc("/auth/check", tokenCheckHandler)
	http.HandleFunc("/auth/del", tokenDelHandler)

	_ = http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	login := r.FormValue("login")
	password := r.FormValue("password")

	if login == "" || password == "" || login != password {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   login,
		"role": "user",
		"exp":  time.Now().AddDate(0, 0, 10).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, _ := token.SignedString(hmacSecret)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"token": tokenString,
	})

}

func tokenCheckHandler(w http.ResponseWriter, r *http.Request) {

	token, code, _ := getToken(r)

	if code == 200 {

		claims, _ := token.Claims.(jwt.MapClaims)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("User-Id", fmt.Sprint(claims["id"]))
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"mes": "successfully",
		})

	}

	http.Error(w, "", code)

}

func tokenDelHandler(w http.ResponseWriter, r *http.Request) {

	token, code, tokenSha := getToken(r)

	if code == 200 {

		claims, _ := token.Claims.(jwt.MapClaims)
		addHash(
			tokenSha,
			uint32(time.Unix(int64(claims["exp"].(float64)), 0).Sub(time.Now()).Seconds()),
		)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("User-Id", fmt.Sprint(claims["id"]))
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"mes": "successfully",
		})

		return
	}

	http.Error(w, "", code)
}

func getToken(r *http.Request) (*jwt.Token, int, string) {

	if r.Method != http.MethodPost {
		return nil, http.StatusMethodNotAllowed, ""
	}

	token := r.Header.Get("Authorization")

	if token == "" {
		return nil, http.StatusUnauthorized, ""
	}
	extractedToken := strings.Split(token, "Bearer ")

	if len(extractedToken) < 2 {
		return nil, http.StatusUnauthorized, ""
	}

	tokenResult, err := jwt.Parse(extractedToken[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSecret, nil
	})

	if err != nil {
		return nil, http.StatusUnauthorized, ""
	}

	tokenSha := Sha512(extractedToken[1])

	if _, ok := tokenResult.Claims.(jwt.MapClaims); ok && tokenResult.Valid && !isSet(tokenSha) {
		return tokenResult, http.StatusOK, tokenSha
	}

	return nil, http.StatusUnauthorized, ""
}

func Sha512(text string) string {
	algorithm := sha512.New()
	algorithm.Write([]byte(text))
	return hex.EncodeToString(algorithm.Sum(nil))
}

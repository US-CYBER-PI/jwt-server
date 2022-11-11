package main

import (
	_interface "JwtServer/interface"
	"JwtServer/repositories"
	"JwtServer/utils"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var (
	pgUser          = "secret"
	pgPassword      = "secret"
	pgHost          = "localhost"
	pgPort          = "5432"
	pgDB            = "jwt"
	pgUserTable     = "users"
	pgLoginField    = "login"
	hmacSecret      = []byte("c4bd7d88edb4fa1817abb11707958924384f7933e5facfd707dc1d1429af9936")
	port            = 9096
	namespace       = "test"
	setName         = "jwt"
	aerospikeHost   = "127.0.0.1"
	aerospikePort   = 3000
	tokenRepository _interface.TokenRepository
	userRepository  _interface.UserRepository
	jwtManager      utils.JwtManager
)

func init() {

	err := godotenv.Load(".env")

	if err != nil {
		log.Println("Error loading .env file")
	}

	if os.Getenv("PG_USER") != "" {
		pgUser = os.Getenv("PG_USER")
	}

	if os.Getenv("PG_PASSWORD") != "" {
		pgPassword = os.Getenv("PG_PASSWORD")
	}

	if os.Getenv("PG_HOST") != "" {
		pgHost = os.Getenv("PG_HOST")
	}

	if os.Getenv("PG_PORT") != "" {
		pgPort = os.Getenv("PG_PORT")
	}

	if os.Getenv("PG_DB") != "" {
		pgDB = os.Getenv("PG_DB")
	}

	if os.Getenv("PG_USER_TABLE") != "" {
		pgUserTable = os.Getenv("PG_USER_TABLE")
	}

	if os.Getenv("PG_LOGIN_FIELD") != "" {
		pgLoginField = os.Getenv("PG_LOGIN_FIELD")
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

	tokenRepository, err = repositories.NewTokenRepositoryAerospike(aerospikeHost, aerospikePort, namespace, setName)

	if err != nil {
		panic(err)
	}

	userRepository, err = repositories.NewUserRepositoryPG(pgHost, pgPort, pgUser, pgPassword, pgDB, pgUserTable, pgLoginField)

	if err != nil {
		panic(err)
	}

	jwtManager = utils.NewJwtManager(hmacSecret, tokenRepository)

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

	authentication, err := userRepository.Authentication(login, password)
	if err != nil {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	tokenString := jwtManager.CreateToken(strconv.Itoa(int(authentication.Id)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"token": tokenString,
	})

}

func tokenCheckHandler(w http.ResponseWriter, r *http.Request) {

	token, code := getToken(r)

	if code == 200 {

		userId := jwtManager.GetTokenId(token)

		if userId == "" {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("User-Id", userId)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"mes": "successfully",
		})

	}

	http.Error(w, "", code)

}

func tokenDelHandler(w http.ResponseWriter, r *http.Request) {

	token, code := getToken(r)

	if code == 200 {
		jwtManager.DeleteToken(token)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"mes": "successfully",
		})

		return
	}

	http.Error(w, "", code)
}

func getToken(r *http.Request) (string, int) {

	if r.Method != http.MethodPost {
		return "", http.StatusMethodNotAllowed
	}

	token := r.Header.Get("Authorization")

	if token == "" {
		return "", http.StatusUnauthorized
	}
	extractedToken := strings.Split(token, "Bearer ")

	if len(extractedToken) < 2 {
		return "", http.StatusUnauthorized
	}

	return extractedToken[1], http.StatusOK
}

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
	pgRoleTable     = "roles"
	pgRoleIdField   = "role_id"
	hmacSecret      = []byte("c4bd7d88edb4fa1817abb11707958924384f7933e5facfd707dc1d1429af9936")
	port            = 9096
	namespace       = "test"
	setName         = "jwt"
	aerospikeHost   = "127.0.0.1"
	aerospikePort   = 3000
	allowedAccesses = map[string][]string{"view": {"user", "admin"}, "create": {"admin"}}
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

	if os.Getenv("PG_ROLE_TABLE") != "" {
		pgRoleTable = os.Getenv("PG_ROLE_TABLE")
	}

	if os.Getenv("PG_ROLE_FIELD") != "" {
		pgRoleIdField = os.Getenv("PG_ROLE_FIELD")
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

	//format: view:user|admin,create:admin
	if os.Getenv("ALLOWED_ACCESSES") != "" {
		for _, val := range strings.Split(os.Getenv("ALLOWED_ACCESSES"), "|") {
			accesses := strings.Split(val, ":")[0]
			roles := strings.Split(val, ":")[1]
			allowedAccesses[accesses] = strings.Split(roles, ",")
		}
	}

}

func main() {

	var err error

	tokenRepository, err = repositories.NewTokenRepositoryAerospike(aerospikeHost, aerospikePort, namespace, setName)

	if err != nil {
		panic(err)
	}

	userRepository, err = repositories.NewUserRepositoryPG(pgHost, pgPort, pgUser, pgPassword, pgDB, pgUserTable, pgRoleTable, pgLoginField, pgRoleIdField)

	if err != nil {
		panic(err)
	}

	jwtManager = utils.NewJwtManager(hmacSecret, tokenRepository)

	http.HandleFunc("/auth/refresh_token", refreshTokenHandler)
	http.HandleFunc("/auth/update/refresh_token", updateRefreshTokenHandler)
	http.HandleFunc("/auth/del", refreshTokenDelHandler)

	http.HandleFunc("/auth/token", tokenHandler)
	http.HandleFunc("/auth/check", tokenCheckHandler)

	_ = http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	phone := r.FormValue("phone")
	password := r.FormValue("password")

	if phone == "" || password == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	authentication, err := userRepository.Authentication(phone, password)
	if err != nil {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	tokenString, exp := jwtManager.CreateRefreshToken(strconv.Itoa(int(authentication.Id)))

	roles, _ := userRepository.GetRoles(int(authentication.Id))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"token":       tokenString,
		"expiredDate": exp,
		"role":        roles[0].Name,
	})

}

func updateRefreshTokenHandler(w http.ResponseWriter, r *http.Request) {

	token, code := getToken(r)

	if code == 200 {

		//TODO add a ban on updating if the token can live more than half of its time
		userId := jwtManager.GetRefreshTokenId(token)
		if userId == "" {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		jwtManager.DeleteRefreshToken(token)
		tokenString, exp := jwtManager.CreateRefreshToken(userId)

		userIdInt, _ := strconv.Atoi(userId)

		roles, _ := userRepository.GetRoles(userIdInt)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"token":       tokenString,
			"expiredDate": exp,
			"role":        roles[0].Name,
		})
		return
	}

	http.Error(w, "", code)
}

func refreshTokenDelHandler(w http.ResponseWriter, r *http.Request) {

	token, code := getToken(r)

	if code == 200 {
		jwtManager.DeleteRefreshToken(token)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"mes": "successfully",
		})

		return
	}

	http.Error(w, "", code)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {

	token, codeToken := getToken(r)
	access, codeAccess := getAccess(r)

	if codeToken == 200 && codeAccess == 200 {

		if _, ok := allowedAccesses[access]; !ok {
			http.Error(w, "", http.StatusForbidden)
			return
		}

		userId := jwtManager.GetRefreshTokenId(token)
		if userId == "" {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		userId32, _ := strconv.Atoi(userId)
		roles, _ := userRepository.GetRoles(userId32)

		for _, role := range roles {
			if utils.Contains(allowedAccesses[access], role.Name) {
				tokenString := jwtManager.CreateToken(userId, access)

				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"token": tokenString,
				})
				return
			}
		}

		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	if codeToken == 200 {
		http.Error(w, "", codeAccess)
	} else {
		http.Error(w, "", codeToken)
	}
}

func tokenCheckHandler(w http.ResponseWriter, r *http.Request) {

	token, codeToken := getToken(r)
	access, codeAccess := getAccess(r)

	if codeToken == 200 && codeAccess == 200 {

		userId, tokenAccess := jwtManager.GetTokenData(token)
		if userId == "" {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		if access != tokenAccess {
			http.Error(w, "", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("User-Id", userId)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"mes": "successfully",
		})

	}

	if codeToken == 200 {
		http.Error(w, "", codeAccess)
	} else {
		http.Error(w, "", codeToken)
	}

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

func getAccess(r *http.Request) (string, int) {

	if r.Method != http.MethodPost {
		return "", http.StatusMethodNotAllowed
	}

	token := r.Header.Get("Access")

	if token == "" {
		return "", http.StatusUnauthorized
	}

	return token, http.StatusOK
}

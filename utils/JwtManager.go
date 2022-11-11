package utils

import (
	_interface "JwtServer/interface"
	"fmt"
	"github.com/golang-jwt/jwt"
	"time"
)

type JwtManager struct {
	hmacSecret      []byte
	tokenRepository _interface.TokenRepository
}

func NewJwtManager(hmacSecret []byte, tokenRepository _interface.TokenRepository) JwtManager {
	return JwtManager{
		hmacSecret:      hmacSecret,
		tokenRepository: tokenRepository,
	}
}

func (j *JwtManager) CreateToken(id string) string {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   id,
		"role": "user",
		"exp":  time.Now().AddDate(0, 0, 10).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, _ := token.SignedString(j.hmacSecret)

	return tokenString
}

func (j *JwtManager) CheckToken(token string) bool {

	tokenR, _ := j.GetToken(token)

	return tokenR != nil
}

func (j *JwtManager) DeleteToken(token string) bool {
	tokenR, tokenSha := j.GetToken(token)

	if tokenR == nil {
		return false
	}

	claims, _ := tokenR.Claims.(jwt.MapClaims)
	j.tokenRepository.AddToken(
		tokenSha,
		uint32(time.Unix(int64(claims["exp"].(float64)), 0).Sub(time.Now()).Seconds()),
	)

	return true
}

func (j *JwtManager) GetTokenId(token string) string {

	tokenR, _ := j.GetToken(token)

	if tokenR == nil {
		return ""
	}

	claims, _ := tokenR.Claims.(jwt.MapClaims)

	return fmt.Sprint(claims["id"])
}

func (j *JwtManager) GetToken(token string) (*jwt.Token, string) {

	tokenResult, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return j.hmacSecret, nil
	})

	if err != nil {
		return nil, ""
	}

	tokenSha := Sha512(token)

	if _, ok := tokenResult.Claims.(jwt.MapClaims); ok && tokenResult.Valid && !j.tokenRepository.IsSet(tokenSha) {
		return tokenResult, tokenSha
	}

	return nil, ""
}
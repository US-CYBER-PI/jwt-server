package _interface

type TokenRepository interface {
	AddToken(token string, seconds uint32) bool
	IsSet(token string) bool
}

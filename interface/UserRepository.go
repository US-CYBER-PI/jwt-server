package _interface

import "JwtServer/models"

type UserRepository interface {
	Authentication(login, password string) (*models.User, error)
	GetRoles(userId int) ([]*models.Role, error)
}

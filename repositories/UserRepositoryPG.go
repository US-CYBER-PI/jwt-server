package repositories

import (
	"JwtServer/models"
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type UserRepositoryPG struct {
	db       *sql.DB
	queryRow string
}

func NewUserRepositoryPG(host, port, user, password, dbname, tableName, loginField string) (*UserRepositoryPG, error) {

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	db, err := sql.Open("postgres", connStr)

	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	return &UserRepositoryPG{
		db:       db,
		queryRow: fmt.Sprintf("SELECT id,%s,password FROM %s WHERE login=$1", loginField, tableName),
	}, nil
}

func (r *UserRepositoryPG) Authentication(login, password string) (*models.User, error) {
	var user models.User

	err := r.db.QueryRow(r.queryRow, login).Scan(&user.Id, &user.Login, &user.Password)

	if err != nil {
		return nil, errors.New("user not found")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))

	if err != nil {
		return nil, errors.New("user not found")
	}

	return &user, nil
}

func (r *UserRepositoryPG) GetRoles(userId int) ([]*models.Role, error) {
	return []*models.Role{
		{Id: 1, Name: "user"},
		{Id: 2, Name: "admin"},
	}, nil
}

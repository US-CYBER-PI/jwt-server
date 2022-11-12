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
	db           *sql.DB
	queryUserRow string
	queryRoleRow string
}

func NewUserRepositoryPG(host, port, user, password, dbname, tableUserName, tableRoleName, loginField, roleIdField string) (*UserRepositoryPG, error) {

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	db, err := sql.Open("postgres", connStr)

	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	return &UserRepositoryPG{
		db:           db,
		queryUserRow: fmt.Sprintf("SELECT id, %s, password FROM %s WHERE %s=$1", loginField, tableUserName, loginField),
		queryRoleRow: fmt.Sprintf("SELECT %s.id, %s.name FROM %s JOIN %s ON %s.%s=%s.id WHERE %s.id=$1",
			tableRoleName,
			tableRoleName,
			tableRoleName,
			tableUserName,
			tableUserName,
			roleIdField,
			tableRoleName,
			tableUserName),
	}, nil
}

func (r *UserRepositoryPG) Authentication(login, password string) (*models.User, error) {
	var user models.User

	err := r.db.QueryRow(r.queryUserRow, login).Scan(&user.Id, &user.Login, &user.Password)

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
	var role models.Role

	_ = r.db.QueryRow(r.queryRoleRow, userId).Scan(&role.Id, &role.Name)
	return []*models.Role{
		&role,
	}, nil
}

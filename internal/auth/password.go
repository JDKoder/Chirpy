package auth

import (
	"github.com/alexedwards/argon2id"
)

var ARGON_PARAMS argon2id.Params = *argon2id.DefaultParams

func HashPassword(password string) (string, error) {
	return argon2id.CreateHash(password, &ARGON_PARAMS)
}

func CheckPasswordHash(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}

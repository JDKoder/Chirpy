package auth

import (
	"fmt"
	"testing"
)

func TestHashPassword(t *testing.T) {

	cases := []string{
		"lowercase",
		"UPPERCASE",
		"alphaABCNumeric1234567890",
		"abcdefghijklmnopqrstuvwxyz",
		"012345678909876543210",
		"!@#$%^&*()_+1234567890-=qwertyuiop[]asdfghjkl;'zxcvbnm,./",
	}

	for _, Case := range cases {
		passToHash := Case
		hashedPass, err := HashPassword(passToHash)
		fmt.Printf("Password: %s ; Hash: %s", passToHash, hashedPass)
		if err != nil {
			t.Errorf("Was not expecting any errors")
		}
		if good, _ := CheckPasswordHash(passToHash, hashedPass); !good {
			t.Errorf("Received Unexpected hash %s from password %s", hashedPass, passToHash)
		}
	}
}

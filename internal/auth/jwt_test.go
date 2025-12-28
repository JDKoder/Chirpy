package auth

import (
	"log"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {

	log.Println("TestMakeJWT")
	//func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	type MakeJWTCase struct {
		userId  uuid.UUID
		secret  string
		expires time.Duration
	}
	MinuteDuration, _ := time.ParseDuration("1m")
	cases := []MakeJWTCase{
		{userId: uuid.New(), secret: "IAmAS3cre3T", expires: MinuteDuration},
	}

	for _, Case := range cases {
		signedToken, err := MakeJWT(Case.userId, Case.secret, Case.expires)
		if err != nil {
			t.Errorf("Was not expecting any errors: %s", err)
			return
		}
		if subject, err := ValidateJWT(signedToken, Case.secret); subject == uuid.Nil {
			t.Errorf("ValidateJWT failed with error %v", err)
			return
		}
	}
}

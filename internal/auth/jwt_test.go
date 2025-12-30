package auth

import (
	"log"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {

	log.Println("TestMakeJWT")
	//func MakeJWT(userID uuid.UUID, tokenjwtSecret string, expiresIn time.Duration) (string, error) {
	type MakeJWTCase struct {
		userId        uuid.UUID
		jwtSecret     string
		validationKey string
		expires       time.Duration
		expectedErr   bool
	}
	MinuteDuration, _ := time.ParseDuration("1m")
	ExpiredDuration, _ := time.ParseDuration("-1m")
	cases := []MakeJWTCase{
		{userId: uuid.New(), jwtSecret: "IAmAS3cre3T", validationKey: "IAmAS3cre3T", expires: MinuteDuration, expectedErr: false},
		{userId: uuid.New(), jwtSecret: "I am Wrong", validationKey: "IAmAS3cre3T", expires: MinuteDuration, expectedErr: true},
		{userId: uuid.New(), jwtSecret: "IAmAS3cre3T", validationKey: "IAmAS3cre3T", expires: ExpiredDuration, expectedErr: true},
	}

	for _, Case := range cases {
		signedToken, err := MakeJWT(Case.userId, Case.jwtSecret, Case.expires)
		if err != nil {
			t.Errorf("Error Creating JWT: %s", err)
			return
		}
		Subject, err := ValidateJWT(signedToken, Case.validationKey)
		if err != nil {
			if !Case.expectedErr {
				t.Errorf("ValidateJWT had an unexpected error %v", err)
				return
			}
		} else {
			if Subject != Case.userId {
				t.Errorf("Subject was incorrect")
			}
		}
	}
}

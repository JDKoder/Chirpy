package auth

import (
	"log"
	"net/http"
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

func TestGetBearerToken(t *testing.T) {
	log.Println("TestGetBearerToken")

	type GBTCase struct {
		hasAuthHeader bool
		authHeader    string
		expected      string
	}

	cases := []GBTCase{
		{
			hasAuthHeader: true,
			authHeader:    "Bearer abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz",
			expected:      "abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz",
		},
		{
			hasAuthHeader: false,
			authHeader:    "",
			expected:      "",
		},
		{
			hasAuthHeader: true,
			authHeader:    "Somethingthatisnotauthorization",
			expected:      "",
		},
	}

	headers := http.Header{}
	token := ""
	var err error

	for _, Case := range cases {
		token = ""
		err = nil
		if Case.hasAuthHeader {
			headers.Set("Authorization", Case.authHeader)
		} else {
			headers.Del("Authorization")
		}
		token, err = GetBearerToken(headers)
		if err != nil {
			if Case.expected != "" {
				t.Errorf("Unexpected Error for authHeader [%s]", Case.authHeader)
			}
		}
		if token != Case.expected {
			t.Errorf("token %s was not expected %s", token, Case.expected)
		}
	}

}

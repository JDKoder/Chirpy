package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{}
	claims.Issuer = "chirpy"
	claims.IssuedAt = jwt.NewNumericDate(time.Now().UTC())
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().UTC().Add(expiresIn))
	claims.Subject = fmt.Sprintf("%s", userID)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(tokenSecret))
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	type CustomClaim struct {
		jwt.RegisteredClaims
	}
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaim{}, func(token *jwt.Token) (any, error) {
		SignIsGood := token.Method == jwt.SigningMethodHS256
		if SignIsGood {
			return []byte(tokenSecret), nil
		}
		log.Println("Invalid JWT: token.Method")
		return []byte(""), fmt.Errorf("Invalid JWT")
	})
	var userID uuid.UUID
	if err != nil {
		return uuid.Nil, err
	} else if claims, ok := token.Claims.(*CustomClaim); ok {
		Subject, _ := claims.GetSubject()
		userID, err = uuid.Parse(Subject)
		if err != nil {
			return userID, fmt.Errorf("Couldn't parse claims.Subject: %s\n", claims.Subject)
		}
	} else {
		log.Fatal("unknown claims type, cannot proceed")
		return uuid.UUID{}, fmt.Errorf("unknown claims")
	}
	return userID, nil
}

func spliceAuthorizationHeader(headers http.Header) ([]string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return []string{}, fmt.Errorf("Authorization header not set\n")
	}
	authSplice := strings.Split(authHeader, " ")
	if len(authSplice) < 2 {
		return []string{}, fmt.Errorf("Bad Authorization Header %s\n", authHeader)
	}
	return authSplice, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authSplice, err := spliceAuthorizationHeader(headers)
	if err != nil {
		return "", fmt.Errorf("Bad Authorization Header: %s", err)
	}
	if authSplice[0] != "Bearer" {
		log.Printf("Authorization header is missing Bearer part")
		return "", fmt.Errorf("Authorization is malformed")
	}
	return authSplice[1], nil
}

func GetAPIKey(headers http.Header) (string, error) {
	AuthorizationValue, err := spliceAuthorizationHeader(headers)
	if err != nil {
		return "", fmt.Errorf("Bad Authorization Header: %s", err)
	}
	if AuthorizationValue[0] != "ApiKey" {
		log.Printf("Authorization header is missing ApiKey part")
		return "", fmt.Errorf("Authorization is malformed.")
	}
	return AuthorizationValue[1], nil
}

func MakeRefreshToken() (string, error) {
	RandomBytes := make([]byte, 32)
	rand.Read(RandomBytes)
	EncodedString := hex.EncodeToString(RandomBytes)
	return EncodedString, nil
}

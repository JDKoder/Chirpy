package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/JDKoder/Chirpy/internal/auth"
	"github.com/JDKoder/Chirpy/internal/database"
	"github.com/google/uuid"
)

type apiConfig struct {
	fileserverHits  atomic.Int32
	dbQueries       *database.Queries
	platform        string
	secretToken     string
	tokenDuration   string
	refreshDuration string
}

type emailBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userDTO struct {
	database.User
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type polkaEventData struct {
	UserID string `json:"user_id"`
}

type polkaEvent struct {
	Event string         `json:"event"`
	Data  polkaEventData `json:"data"`
}

func (config *apiConfig) handlePolkaWebookEvent(w http.ResponseWriter, req *http.Request) {
	PolkaEvent := polkaEvent{}
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&PolkaEvent)
	if err != nil {
		log.Printf("Couldn't decode json body to polkaEvent: %s", err)
		w.WriteHeader(500)
		return
	}
	switch PolkaEvent.Event {
	case "user.upgraded":
		UserUUID, uuidParseErr := uuid.Parse(PolkaEvent.Data.UserID)
		log.Printf("Attempting user.upgraded on UserId %s", PolkaEvent.Data.UserID)
		if uuidParseErr != nil {
			log.Printf("Could not parse UUID from event userid %s", PolkaEvent.Data.UserID)
			w.WriteHeader(http.StatusInternalServerError)
		}
		Params := database.UpdateUserChirpyRedParams{IsChirpyRed: true, ID: UserUUID}
		updated, err := config.dbQueries.UpdateUserChirpyRed(req.Context(), Params)
		log.Printf("User %s upgraded: %t\n", updated.Email, updated.IsChirpyRed)
		if err != nil {
			log.Printf("UpdateUserChirpyRed failed. event body: %v", PolkaEvent)
			w.WriteHeader(http.StatusNotFound)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		w.WriteHeader(http.StatusNoContent)
		return
	}
}

func (config *apiConfig) incrementFileserverHits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		log.Print("increment hit")
		config.fileserverHits.Add(1)
		next.ServeHTTP(rw, req)
	})
}

func (config *apiConfig) deleteChirpByID(w http.ResponseWriter, req *http.Request) {

	accessToken, err := auth.GetBearerToken(req.Header)
	userID, err := auth.ValidateJWT(accessToken, config.secretToken)
	if err != nil {
		log.Printf("updateUser: bad access token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	chirpId := req.PathValue("chirpId")
	chirpUUID, err := uuid.Parse(chirpId)
	if err != nil {
		log.Printf("Couldn't parse uuid from chirpid %s", chirpId)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	chirp, err := config.dbQueries.GetChirp(req.Context(), chirpUUID)
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "sql: no rows in result set") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		log.Printf("GetChirp failed with error: %s", err)
		return
	}
	if chirp.UserID != userID {
		log.Printf("Unauthorized deletion of another user's chirp\n")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	err = config.dbQueries.DeleteChirp(req.Context(), chirpUUID)
	if err != nil {
		log.Printf("DeleteChirp failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (config *apiConfig) getChirpById(w http.ResponseWriter, req *http.Request) {
	chirpId := req.PathValue("chirpId")
	chirpUUID, err := uuid.Parse(chirpId)
	if err != nil {
		log.Printf("Couldn't parse uuid from chirpid %s", chirpId)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	chirp, err := config.dbQueries.GetChirp(req.Context(), chirpUUID)
	if err != nil {
		if strings.Contains(fmt.Sprintf("%s", err), "sql: no rows in result set") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		log.Printf("GetChirp failed with error: %s", err)
		return
	}
	dat, err := json.Marshal(chirp)
	if err != nil {
		log.Printf("Couldn't marshal Chirp from object %v", chirp)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

func (config *apiConfig) getChirp(w http.ResponseWriter, req *http.Request) {
	qChirps, err := config.dbQueries.GetChirps(req.Context())
	if err != nil {
		log.Printf("GetChirps encountered error: %s", err)
		w.WriteHeader(500)
		return
	}
	dat, err := json.Marshal(qChirps)
	if err != nil {
		log.Printf("Couldn't marshal Chirps from object %v", qChirps)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

func (config *apiConfig) updateUser(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	reqEmail := emailBody{}
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&reqEmail)
	if err != nil {
		log.Printf("Couldn't decode json body to emailBody: %s", err)
		w.WriteHeader(500)
		return
	}
	hashedPass, err := auth.HashPassword(reqEmail.Password)
	accessToken, err := auth.GetBearerToken(req.Header)
	userID, err := auth.ValidateJWT(accessToken, config.secretToken)
	if err != nil {
		log.Printf("updateUser: bad access token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user, err := config.dbQueries.UpdateUser(req.Context(), database.UpdateUserParams{Email: reqEmail.Email, HashedPassword: hashedPass, ID: userID})
	if err != nil {
		log.Printf("updateUser: unable to updateUser %s\n", userID.String())
		w.WriteHeader(http.StatusInternalServerError)
	}
	log.Println("marshalling")
	marshalUserDTO(user, w, http.StatusOK)
}

func marshalUserDTO(user database.User, w http.ResponseWriter, successStatus int) {
	user.HashedPassword = ""
	dat, err := json.Marshal(user)
	if err != nil {
		log.Printf("error marshalling error: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(successStatus)
	w.Write(dat)
}

func (config *apiConfig) createUser(w http.ResponseWriter, req *http.Request) {
	reqEmail := emailBody{}
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&reqEmail)
	if err != nil {
		log.Printf("Couldn't decode json body to emailBody: %s", err)
		w.WriteHeader(500)
		return
	}
	hashedPass, err := auth.HashPassword(reqEmail.Password)
	user, userErr := config.dbQueries.CreateUser(
		req.Context(),
		database.CreateUserParams{Email: reqEmail.Email, HashedPassword: hashedPass},
	)
	if userErr != nil {
		log.Printf("Failed to create user given e-mail [%s]: %s", reqEmail.Email, userErr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	marshalUserDTO(user, w, http.StatusCreated)
}

func (config *apiConfig) revoke(w http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Token is malformed: %s", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	err = config.dbQueries.RevokeToken(req.Context(), refreshToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (config *apiConfig) refresh(w http.ResponseWriter, req *http.Request) {

	type refreshTokenResponse struct {
		Token string `json:"token"`
	}

	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Token is malformed: %s", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ExistingRefreshToken, err := config.dbQueries.GetRefreshToken(req.Context(), refreshToken)
	if err != nil {
		log.Printf("No existing token found for given auth.\n")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if time.Now().After(ExistingRefreshToken.ExpiresAt) {
		log.Printf("Token expired")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if ExistingRefreshToken.RevokedAt.Valid {
		log.Printf("Token revoked")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	AuthToken, err := auth.MakeJWT(ExistingRefreshToken.UserID, config.secretToken, getTokenDuration(config.tokenDuration))
	if err != nil {
		log.Printf("refreshing with new jwt failed.\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	dto := refreshTokenResponse{
		Token: AuthToken,
	}
	dat, err := json.Marshal(dto)
	if err != nil {
		log.Printf("error marshalling error: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Printf("refresh generated a new token with dto %s", dat)
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

/**
* Utility function to reduce boilerplate error checking for parsing failures.
* Will cause panic if the input string cannot be parsed.  Should only be used
* with environment set known parsable values, or unit tests.
* @RefactorCandidate
**/
func getTokenDuration(durationStr string) time.Duration {
	TokenDuration, err := time.ParseDuration(durationStr)
	if err != nil {
		log.Fatalf("unable to parse the duration set in the environment %s\n", durationStr)
		panic("environment token duration is unparsable")
	}
	return TokenDuration
}

func (config *apiConfig) userLogin(w http.ResponseWriter, req *http.Request) {
	login := emailBody{}
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&login)
	if err != nil {
		log.Printf("Couldn't decode json body to emailBody: %s", err)
		w.WriteHeader(500)
		return
	}
	user, _ := config.dbQueries.GetUser(req.Context(), login.Email)
	if good, _ := auth.CheckPasswordHash(login.Password, user.HashedPassword); !good {
		log.Printf("Login failed for e-mail: %s\n", login.Email)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user.HashedPassword = ""
	jwt, err := auth.MakeJWT(user.ID, config.secretToken, getTokenDuration(config.tokenDuration))
	RefreshToken, _ := auth.MakeRefreshToken()
	RefreshDuration := getTokenDuration(config.refreshDuration)
	RefreshExpiration := time.Now().Add(RefreshDuration)
	CreateRefreshTokenParams := database.CreateRefreshTokenParams{
		Token:     RefreshToken,
		UserID:    user.ID,
		ExpiresAt: RefreshExpiration,
	}
	DBRefreshToken, err := config.dbQueries.CreateRefreshToken(
		req.Context(),
		CreateRefreshTokenParams,
	)
	if err != nil {
		log.Printf("Unable to generate a refresh token for the user. token: %s, userid: %s, expiresat: %s", RefreshToken, user.ID.String(), RefreshExpiration.String())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	dto := userDTO{
		database.User{ID: user.ID, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Email: user.Email, IsChirpyRed: user.IsChirpyRed},
		jwt,
		DBRefreshToken.Token,
	}
	dat, err := json.Marshal(dto)
	if err != nil {
		log.Printf("error marshalling error: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

func (config *apiConfig) fileserverMetricsHandler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	//io.WriteString(w, fmt.Sprintf("Hits: %d", config.fileserverHits.Load()))
	io.WriteString(w, fmt.Sprintf(`
		<html>
			<body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
		  </body>
		</html>`, config.fileserverHits.Load()))
}

func (config *apiConfig) resetAll(w http.ResponseWriter, req *http.Request) {
	if config.platform != "dev" {
		w.WriteHeader(403)
		log.Printf("Action forbidden in this environment")
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "Resetting metrics, Deleting Users")
	config.fileserverHits.Store(0)
	//resetting all users
	config.dbQueries.DeleteUsers(req.Context())
}

func (config *apiConfig) chirp(w http.ResponseWriter, req *http.Request) {
	type chirpBody struct {
		Body   string    `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}
	type chirpError struct {
		Error string `json:"error"`
	}
	type isValid struct {
		//IsValid bool `json:"valid"`
		CleanedBody string `json:"cleaned_body"`
	}
	reqjwt, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Token is malformed: %s", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ID, err := auth.ValidateJWT(reqjwt, config.secretToken)
	if err != nil {
		log.Printf("JWT is invalid: %s", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	validating := chirpBody{}
	decoder := json.NewDecoder(req.Body)
	err = decoder.Decode(&validating)
	log.Printf("userid: %s, body %s", ID, validating.Body)
	if err != nil {
		errorResponse := chirpError{Error: fmt.Sprintf("Error Decoding response %s", err)}
		w.WriteHeader(http.StatusInternalServerError)
		dat, err := json.Marshal(errorResponse)
		if err != nil {
			log.Printf("error marshalling error: %s", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(dat)
		return
	}
	if len(validating.Body) > 140 {
		errorResponse := chirpError{Error: "Chirp is too long"}
		w.WriteHeader(http.StatusBadRequest)
		dat, err := json.Marshal(errorResponse)
		if err != nil {
			log.Printf("error marshalling error: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(dat)
		return
	}
	cleanLanguage(&validating.Body)
	qresp, err := config.dbQueries.AddChirp(req.Context(), database.AddChirpParams{Body: validating.Body, UserID: ID})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("AddChirp failed with error: %s", err)
		return
	}
	validDat, err := json.Marshal(qresp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("Error marshalling validated: %s", err)
		return
	}
	w.WriteHeader(201)
	w.Write(validDat)
}

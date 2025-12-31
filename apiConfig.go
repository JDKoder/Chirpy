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

func (config *apiConfig) incrementFileserverHits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		log.Print("increment hit")
		config.fileserverHits.Add(1)
		next.ServeHTTP(rw, req)
	})
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
	user.HashedPassword = ""
	dat, err := json.Marshal(user)
	if err != nil {
		log.Printf("error marshalling error: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write(dat)
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
	//TODO: Handle scenario where user's email is not found
	user, _ := config.dbQueries.GetUser(req.Context(), login.Email)
	if good, _ := auth.CheckPasswordHash(login.Password, user.HashedPassword); !good {
		log.Printf("Login failed for e-mail: %s\n", login.Email)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user.HashedPassword = ""
	tokenExpiration, err := time.ParseDuration(config.tokenDuration)
	if err != nil {
		log.Printf("unable to parse the duration set in the environment %s", config.tokenDuration)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	jwt, err := auth.MakeJWT(user.ID, config.secretToken, tokenExpiration)
	RefreshToken, _ := auth.MakeRefreshToken()
	//TODO: Add RefreshToken record to database
	dto := userDTO{
		database.User{ID: user.ID, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Email: user.Email},
		jwt,
		RefreshToken,
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

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/JDKoder/Chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var (
	serverMux = http.NewServeMux()
	cfg       = apiConfig{fileserverHits: atomic.Int32{}}
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
}

func (config *apiConfig) ServeHTTP(w http.ResponseWriter, req *http.Request) {

}

func (config *apiConfig) incrementFileserverHits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		log.Print("increment hit")
		config.fileserverHits.Add(1)
		next.ServeHTTP(rw, req)
	})
}

func main() {
	//load .env into environment
	godotenv.Load()
	//retrieve DB_URL value
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)

	if err != nil {
		log.Printf("Couldn't open database connection: %s", err)
	}
	dbQueries := database.New(db)

	cfg.dbQueries = dbQueries
	cfg.platform = os.Getenv("PLATFORM")

	s := &http.Server{
		Addr:           ":8080",
		Handler:        serverMux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	const API_PREFIX = "/api"
	const ADMIN_PREFIX = "/admin"
	const API_METRICS = ADMIN_PREFIX + "/metrics"
	const API_RESET = ADMIN_PREFIX + "/reset"
	const API_HEALTHZ = API_PREFIX + "/healthz"
	const API_VALIDATE_CHIRP = API_PREFIX + "/validate_chirp"
	const API_USERS = API_PREFIX + "/users"
	const API_CHIRPS = API_PREFIX + "/chirps"
	const API_CHIRPS_BY_ID = API_CHIRPS + "/{chirpId}"
	fs := http.FileServer(http.Dir("."))
	serverMux.Handle("/app/", cfg.incrementFileserverHits(http.StripPrefix("/app", fs)))
	//healthz should only response to get requests
	serverMux.HandleFunc("GET "+API_HEALTHZ, healthHandler)
	//metrics should only response to GET requests
	serverMux.HandleFunc("GET "+API_METRICS, cfg.fileserverMetricsHandler)
	serverMux.HandleFunc("POST "+API_RESET, cfg.resetAll)
	serverMux.HandleFunc("POST "+API_USERS, cfg.createUser)
	serverMux.HandleFunc("POST "+API_CHIRPS, cfg.chirp)
	serverMux.HandleFunc("GET "+API_CHIRPS, cfg.getChirp)
	serverMux.HandleFunc("GET "+API_CHIRPS_BY_ID, cfg.getChirpById)
	s.ListenAndServe()
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
	}
	w.WriteHeader(http.StatusOK)
	w.Write(dat)
}

func (config *apiConfig) createUser(w http.ResponseWriter, req *http.Request) {
	type emailBody struct {
		Email string `json:"email"`
	}
	reqEmail := emailBody{}
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&reqEmail)
	if err != nil {
		log.Printf("Couldn't decode json body to emailBody: %s", err)
		w.WriteHeader(500)
		return
	}
	user, userErr := config.dbQueries.CreateUser(req.Context(), reqEmail.Email)
	if userErr != nil {
		log.Printf("Failed to create user given e-mail [%s]: %s", reqEmail.Email, userErr)
		w.WriteHeader(500)
		return
	}
	dat, err := json.Marshal(user)
	if err != nil {
		log.Printf("error marshalling error: %s", err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write(dat)
}

func healthHandler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "OK")
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
	validating := chirpBody{}
	decoder := json.NewDecoder(req.Body)

	err := decoder.Decode(&validating)

	log.Printf("userid: %s, body %s", validating.UserID, validating.Body)
	if err != nil {
		errorResponse := chirpError{Error: fmt.Sprintf("Error Decoding response %s", err)}
		w.WriteHeader(500)
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
		w.WriteHeader(400)
		dat, err := json.Marshal(errorResponse)
		if err != nil {
			log.Printf("error marshalling error: %s", err)
			return
		}
		w.Write(dat)
		return
	}

	cleanLanguage(&validating.Body)
	qresp, err := config.dbQueries.AddChirp(req.Context(), database.AddChirpParams{Body: validating.Body, UserID: validating.UserID})
	if err != nil {
		log.Printf("AddChirp failed with error: %s", err)
	}
	//Validated := isValid{IsValid: true}
	validDat, err := json.Marshal(qresp)
	if err != nil {
		log.Printf("Error marshalling validated: %s", err)
		return
	}
	w.WriteHeader(201)
	w.Write(validDat)
}

func cleanLanguage(words *string) {
	wordsSlice := strings.Split(*words, " ")
	for i, word := range wordsSlice {
		badWords := []string{"kerfuffle", "sharbert", "fornax"}
		if slices.Contains(badWords, strings.ToLower(word)) {
			wordsSlice[i] = "****"
		}
	}
	*words = strings.Join(wordsSlice, " ")
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

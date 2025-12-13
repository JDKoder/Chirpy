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
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var (
	serverMux = http.NewServeMux()
	cfg       = apiConfig{fileserverHits: atomic.Int32{}}
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries           *database.Queries
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
	cfg.dbQueries   = dbQueries
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

	fs := http.FileServer(http.Dir("."))
	serverMux.Handle("/app/", cfg.incrementFileserverHits(http.StripPrefix("/app", fs)))
	//healthz should only response to get requests
	serverMux.HandleFunc("GET "+API_HEALTHZ, healthHandler)
	//metrics should only response to GET requests
	serverMux.HandleFunc("GET "+API_METRICS, cfg.fileserverMetricsHandler)
	serverMux.HandleFunc("POST "+API_RESET, cfg.resetMetricsHandler)
	serverMux.HandleFunc("POST "+API_VALIDATE_CHIRP, validateChirp)
	s.ListenAndServe()
}

func healthHandler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "OK")
}

func validateChirp(w http.ResponseWriter, req *http.Request) {
	type validateBody struct {
		Body string `json:"body"`
	}
	type chirpError struct {
		Error string `json:"error"`
	}
	type isValid struct {
		//IsValid bool `json:"valid"`
		CleanedBody string `json:"cleaned_body"`
	}
	validating := validateBody{}
	decoder := json.NewDecoder(req.Body)

	err := decoder.Decode(&validating)

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

	//Validated := isValid{IsValid: true}
	Validated := isValid{CleanedBody: validating.Body}
	validDat, err := json.Marshal(Validated)
	if err != nil {
		log.Printf("Error marshalling validated: %s", err)
		return
	}
	w.WriteHeader(200)
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

func (config *apiConfig) resetMetricsHandler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "Resetting metrics")
	config.fileserverHits.Store(0)
}

package main

import (
	"database/sql"
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
	cfg.secretToken = os.Getenv("INTERNAL_SECRET")
	cfg.tokenDuration = os.Getenv("DEFAULT_TOKEN_DURATION")

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
	const API_LOGIN = API_PREFIX + "/login"
	const API_CHIRPS = API_PREFIX + "/chirps"
	const API_CHIRPS_BY_ID = API_CHIRPS + "/{chirpId}"
	fs := http.FileServer(http.Dir("."))
	serverMux.Handle("/app/", cfg.incrementFileserverHits(http.StripPrefix("/app", fs)))
	serverMux.HandleFunc("GET "+API_HEALTHZ, healthHandler)
	serverMux.HandleFunc("GET "+API_METRICS, cfg.fileserverMetricsHandler)
	serverMux.HandleFunc("POST "+API_RESET, cfg.resetAll)
	serverMux.HandleFunc("POST "+API_USERS, cfg.createUser)
	serverMux.HandleFunc("POST "+API_LOGIN, cfg.userLogin)
	serverMux.HandleFunc("POST "+API_CHIRPS, cfg.chirp)
	serverMux.HandleFunc("GET "+API_CHIRPS, cfg.getChirp)
	serverMux.HandleFunc("GET "+API_CHIRPS_BY_ID, cfg.getChirpById)
	s.ListenAndServe()
}

func healthHandler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "OK")
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

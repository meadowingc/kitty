package main

import (
	"encoding/json"
	"kitty/constants"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/cors"

	"gorm.io/gorm"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"

	"gorm.io/driver/sqlite"
)

var db *gorm.DB

func main() {
	initDatabase()
	r := initRouter()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	const portNum = ":6235"
	go func() {
		log.Printf("Running on http://localhost%s", portNum)
		if err := http.ListenAndServe(portNum, r); err != nil {
			log.Printf("HTTP server stopped: %v", err)
		}
	}()

	// Block until a signal is received
	<-signals
	log.Println("Shutting down gracefully...")

	// Close the database connection
	sqlDB, err := db.DB()
	if err != nil {
		log.Printf("Error on closing database connection: %v", err)
	} else {
		if err := sqlDB.Close(); err != nil {
			log.Printf("Error on closing database connection: %v", err)
		}
	}
}

func initDatabase() {
	var err error
	db, err = gorm.Open(sqlite.Open("file:kitty.db?cache=shared&mode=rwc&_journal_mode=WAL"), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// Migrate the schema
	err = db.AutoMigrate(&Post{}, &AdminUser{})
	if err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}
}

func initRouter() *chi.Mux {

	r := chi.NewRouter()

	CORSMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	})

	r.Use(CORSMiddleware.Handler)
	r.Use(RealIPMiddleware)
	r.Use(middleware.Logger)
	r.Use(httprate.LimitByIP(100, time.Minute)) // general rate limiter for all routes (shared across all routes)
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, r, "home", nil)
	})

	r.Get("/terms-and-conditions", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, r, "terms_and_conditions", nil)
	})
	r.HandleFunc("/signin", userSignIn)
	r.HandleFunc("/signup", userSignUp)
	r.Post("/logout", userLogout)

	r.With(AuthMiddleware).Route("/dashboard", func(r chi.Router) {
		r.Get("/", userPostList)

		r.HandleFunc("/post/new", createPost)
		r.HandleFunc("/post/{postID}", editPost)
	})

	r.Get("/post/{postID}", publicViewPost)

	fileServer := http.FileServer(http.Dir("./assets"))
	r.Handle("/assets/*", http.StripPrefix("/assets", fileServer))

	r.Route("/api", func(r chi.Router) {
		r.Route("/v1", func(r chi.Router) {
			r.Get("/get-user-posts-messages/{userID}", func(w http.ResponseWriter, r *http.Request) {
				guestbookID := chi.URLParam(r, "userID")

				var posts []Post
				guestbookIDUint, err := strconv.ParseUint(guestbookID, 10, 64)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}

				result := db.Where(&Post{AdminUserID: uint(guestbookIDUint)}).
					Limit(constants.MAX_POSTS_TO_SHOW).
					Find(&posts)
				if result.Error != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(posts)
			})
		})
	})

	return r
}

// RealIPMiddleware extracts the client's real IP address from the
// X-Forwarded-For header and sets it on the request's RemoteAddr field. Useful
// for when the app is running behind a reverse proxy
func RealIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// This assumes the first IP in the X-Forwarded-For list is the client's real IP
			// This may need to be adjusted depending on your reverse proxy setup
			i := strings.Index(xff, ", ")
			if i == -1 {
				i = len(xff)
			}
			r.RemoteAddr = xff[:i]
		}
		next.ServeHTTP(w, r)
	})
}

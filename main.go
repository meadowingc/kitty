package main

import (
	"encoding/json"
	"kitty/constants"
	"kitty/database"
	"kitty/site"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/cors"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
)

func main() {
	_ = database.GetDB() // force database initialization
	r := initRouter()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	const portNum = ":6835"
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
	database.CloseDB()
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
	r.Use(site.RealIPMiddleware)
	r.Use(middleware.Logger)
	r.Use(httprate.LimitByIP(100, time.Minute)) // general rate limiter for all routes (shared across all routes)
	r.Use(middleware.Recoverer)
	r.Use(site.TryPutUserInContextMiddleware)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		site.RenderTemplate(w, r, "home", nil)
	})

	r.Get("/terms-and-conditions", func(w http.ResponseWriter, r *http.Request) {
		site.RenderTemplate(w, r, "terms_and_conditions", nil)
	})
	r.HandleFunc("/signinsite.", site.UserSignIn)
	r.HandleFunc("/signupsite.", site.UserSignUp)
	r.Post("/logoutsite.", site.UserLogout)

	r.With(site.AuthProtectedMiddleware).Route("/dashboard", func(r chi.Router) {
		r.Get("/", site.UserPostList)

		r.HandleFunc("/import", site.ImportPosts)

		r.HandleFunc("/post/new", site.CreatePost)
		r.HandleFunc("/post/{postID}", site.EditPost)
		r.HandleFunc("/post/{postID}/delete", site.DeletePost)
	})

	r.Get("/post/{postID}", site.PublicViewPost)
	r.Get("/u/{userID}", site.PublicViewUser)

	fileServer := http.FileServer(http.Dir("./assets"))
	r.Handle("/assets/*", http.StripPrefix("/assets", fileServer))

	r.Route("/api", func(r chi.Router) {
		r.Route("/v1", func(r chi.Router) {
			r.Get("/get-user-posts-messages/{userID}", func(w http.ResponseWriter, r *http.Request) {
				guestbookID := chi.URLParam(r, "userID")

				var posts []database.Post
				guestbookIDUint, err := strconv.ParseUint(guestbookID, 10, 64)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}

				result := database.GetDB().Where(&database.Post{AdminUserID: uint(guestbookIDUint)}).
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

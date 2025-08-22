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
	"github.com/gorilla/csrf"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file if present (non-fatal if missing)
	_ = godotenv.Load()

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
	r.Use(httprate.LimitByIP(50, time.Minute)) // general rate limiter for all routes (shared across all routes)

	if constants.DEBUG_MODE {
		r.Use(site.PlaintextCSRFMiddleware) // mark plaintext requests before CSRF middleware
	}

	csrfKey := os.Getenv("CSRF_AUTH_KEY")
	if csrfKey == "" {
		log.Fatal("CSRF_AUTH_KEY not set. Provide a 32+ byte secret via environment or .env file.\nExample (bash): echo CSRF_AUTH_KEY=$(openssl rand -base64 32) >> .env")
	}
	trustedOrigins := []string{
		"http://localhost:6835",
		"http://127.0.0.1:6835",
		"http://[::1]:6835",
		"https://kitty.meadow.cafe",
	}

	csrfMiddleware := csrf.Protect([]byte(csrfKey),
		csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if constants.DEBUG_MODE {
				log.Printf("CSRF failure: %v host=%s referer=%s origin=%s xfp=%s", csrf.FailureReason(r), r.Host, r.Referer(), r.Header.Get("Origin"), r.Header.Get("X-Forwarded-Proto"))
			}
			http.Error(w, "Forbidden - CSRF token invalid", http.StatusForbidden)
		})),
		csrf.Path("/"),
		csrf.SameSite(csrf.SameSiteLaxMode),
		csrf.TrustedOrigins(trustedOrigins),
		csrf.Secure(!constants.DEBUG_MODE),
	)

	r.Use(csrfMiddleware)
	r.Use(site.NoCacheForHTML)
	// r.Use(middleware.Recoverer)
	r.Use(site.TryPutUserInContextMiddleware)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		type homePost struct {
			Title         string
			Slug          string
			PublishedDate time.Time
			Username      string
		}

		var recent []homePost
		database.GetDB().Table("posts").
			Select("posts.title, posts.slug, posts.published_date, admin_users.username").
			Joins("JOIN admin_users ON admin_users.id = posts.admin_user_id").
			Where("posts.published = ? AND posts.is_page = ? AND posts.show_on_homepage = ?", true, false, true).
			Order("posts.published_date desc").
			Limit(constants.HOMEPAGE_RECENT_POSTS_LIMIT).
			Scan(&recent)

		site.RenderTemplate(w, r, "home", struct {
			Posts []homePost
		}{Posts: recent})
	})

	r.Get("/terms-and-conditions", func(w http.ResponseWriter, r *http.Request) {
		site.RenderTemplate(w, r, "terms_and_conditions", nil)
	})
	r.HandleFunc("/signin", site.UserSignIn)
	r.HandleFunc("/signup", site.UserSignUp)
	r.Post("/logout", site.UserLogout)

	r.With(site.AuthProtectedMiddleware).Route("/dashboard", func(r chi.Router) {
		r.Get("/", site.UserDashboardHome)
		r.Get("/list-posts", site.UserPostList)
		r.Get("/list-pages", site.UserPageList)

		r.HandleFunc("/import", site.ImportPosts)

		r.HandleFunc("/post/new", site.CreatePost)
		r.HandleFunc("/post/{postID}", site.UpdatePost)
		r.HandleFunc("/post/{postID}/delete", site.DeletePost)
		r.HandleFunc("/settings", site.UserSettings)
		r.HandleFunc("/delete-account", site.UserDeleteAccount)
	})

	r.Get("/u/{username}/feed.xml", site.PublicUserRSSFeed)
	r.Get("/u/{username}/tag/{tag}", site.PublicViewUserTag)
	r.Get("/u/{username}/archive", site.PublicViewUserArchive)
	r.Get("/u/{username}/{slug}", site.PublicViewPostBySlug)
	r.Get("/u/{userID:[0-9]+}", site.PublicViewUser)
	r.Get("/u/{username}", site.PublicViewUserByUsername)
	r.Get("/post/{postID}", site.PublicViewPost)

	fileServer := http.FileServer(http.Dir("./assets"))
	r.Handle("/assets/*", http.StripPrefix("/assets", fileServer))

	r.Route("/api", func(r chi.Router) {
		r.Route("/v1", func(r chi.Router) {
			// stricter limits on api endpoints
			r.Use(httprate.LimitByIP(10, time.Minute))
			r.Get("/get-user-posts-messages/{userID}", func(w http.ResponseWriter, r *http.Request) {

				userID := chi.URLParam(r, "userID")

				var posts []database.Post
				userIDUint, err := strconv.ParseUint(userID, 10, 64)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}

				result := database.GetDB().Where(&database.Post{AdminUserID: uint(userIDUint)}).
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

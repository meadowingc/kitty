package main

import (
	"fmt"
	"kitty/constants"
	"kitty/database"
	"kitty/site"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
	"github.com/gorilla/csrf"
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

	go site.StartGeminiServer()

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
	r.Use(Logger)
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
		constants.PUBLIC_URL,
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

		// Routes that require post ownership validation
		r.With(site.PostOwnershipMiddleware).HandleFunc("/post/{postID}", site.UpdatePost)
		r.With(site.PostOwnershipMiddleware).Get("/post/{postID}/check", site.CheckPostUpdatedAt)
		r.With(site.PostOwnershipMiddleware).HandleFunc("/post/{postID}/delete", site.DeletePost)

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
			r.Get("/get-user-posts-messages/{userID}", site.GetUserPostsMessagesAPI)
		})
	})

	return r
}

func Logger(next http.Handler) http.Handler {
	// Define color functions
	gray := color.New(color.FgHiBlack).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap writer to capture status and bytes
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request
		next.ServeHTTP(ww, r)

		// Compute duration
		duration := time.Since(start)

		// Determine level and status coloring
		var level, statusStr string
		switch {
		case ww.statusCode >= 500:
			level = "ERROR"
			statusStr = color.New(color.FgRed).Sprintf("%d", ww.statusCode)
		case ww.statusCode >= 400:
			level = "WARN"
			statusStr = color.New(color.FgYellow).Sprintf("%d", ww.statusCode)
		case ww.statusCode >= 300:
			level = "INFO"
			statusStr = color.New(color.FgCyan).Sprintf("%d", ww.statusCode)
		default: // 2xx and others
			level = "INFO"
			statusStr = color.New(color.FgGreen).Sprintf("%d", ww.statusCode)
		}

		// Duration coloring
		var durStr string
		switch {
		case duration > 500*time.Millisecond:
			durStr = color.New(color.FgRed).Sprintf("%v", duration)
		case duration > 100*time.Millisecond:
			durStr = color.New(color.FgYellow).Sprintf("%v", duration)
		default:
			durStr = color.New(color.FgGreen).Sprintf("%v", duration)
		}

		// Size formatting
		var sizeStr string
		switch {
		case ww.bytesWritten > 1024*1024:
			sizeStr = fmt.Sprintf("%.1fMB", float64(ww.bytesWritten)/(1024*1024))
		case ww.bytesWritten > 1024:
			sizeStr = fmt.Sprintf("%.1fKB", float64(ww.bytesWritten)/1024)
		default:
			sizeStr = fmt.Sprintf("%dB", ww.bytesWritten)
		}

		log.Printf("%s %s %s %s %s %s",
			gray(fmt.Sprintf("[%s]", level)),
			blue(r.Method),
			magenta(r.URL.Path),
			statusStr,
			durStr,
			gray(fmt.Sprintf("(%s)", sizeStr)),
		)
	})
}

// responseWriter captures status code and bytes written
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
	wroteHeader  bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.statusCode = code
	rw.wroteHeader = true
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

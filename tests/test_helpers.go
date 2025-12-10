package tests

import (
	"context"
	"fmt"
	"kitty/database"
	"kitty/site"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
)

const (
	testPort    = "8888"
	testBaseURL = "http://localhost:" + testPort
	testDBPath  = "kitty_test.db"
)

var (
	testServer *http.Server
	browser    *rod.Browser
)

// setupTestEnvironment initializes the test database and server
func setupTestEnvironment(t *testing.T) {
	// Change to parent directory so relative paths work
	if err := os.Chdir(".."); err != nil {
		t.Fatalf("Failed to change to parent directory: %v", err)
	}
	t.Cleanup(func() {
		os.Chdir("tests")
	})

	// Close any existing database connection first
	database.CloseDB()

	// Remove existing test database
	os.Remove("tests/" + testDBPath)
	os.Remove("tests/" + testDBPath + "-shm")
	os.Remove("tests/" + testDBPath + "-wal")

	// Set environment variable for test database
	oldDBPath := os.Getenv("KITTY_DB_PATH")
	os.Setenv("KITTY_DB_PATH", "tests/"+testDBPath)
	t.Cleanup(func() {
		if oldDBPath != "" {
			os.Setenv("KITTY_DB_PATH", oldDBPath)
		} else {
			os.Unsetenv("KITTY_DB_PATH")
		}
	})

	// Initialize database
	db := database.GetDB()
	if db == nil {
		t.Fatal("Failed to initialize test database")
	}

	// Start test server
	startTestServer(t)

	// Initialize browser for this test
	l := launcher.New().Headless(true).MustLaunch()
	browser = rod.New().ControlURL(l).MustConnect()
	t.Cleanup(func() {
		browser.MustClose()
	})

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)
}

func startTestServer(t *testing.T) {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(site.TryPutUserInContextMiddleware)

	// Public routes - simplified home for testing
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Home"))
	})
	r.HandleFunc("/signin", site.UserSignIn)
	r.HandleFunc("/signup", site.UserSignUp)
	r.Post("/logout", site.UserLogout)

	// Public user routes
	r.Get("/u/{username}", site.PublicViewUserByUsername)
	r.Get("/u/{username}/{slug}", site.PublicViewPostBySlug)
	r.Get("/u/{username}/archive", site.PublicViewUserArchive)
	r.Get("/u/{username}/tag/{tag}", site.PublicViewUserTag)
	r.Get("/u/{username}/feed.xml", site.PublicUserRSSFeed)

	// Dashboard routes (protected)
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

	// Serve static files
	r.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets"))))

	testServer = &http.Server{
		Addr:    ":" + testPort,
		Handler: r,
	}

	go func() {
		if err := testServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Test server error: %v", err)
		}
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		testServer.Shutdown(ctx)
	})
}

// TestUser represents a test user
type TestUser struct {
	Username string
	Password string
	Page     *rod.Page
	Context  *rod.Browser // The incognito browser context
}

// createTestUser creates a new user via the signup page
func createTestUser(t *testing.T, username, password string) *TestUser {
	// Create a new incognito browser context for each user to isolate cookies
	incognito := browser.MustIncognito()
	page := incognito.MustPage(testBaseURL + "/signup")

	// Wait for the form to be ready
	page.MustElement("#username").MustInput(username)
	page.MustElement("#password").MustInput(password)
	page.MustElement("button[type=submit]").MustClick()

	// Wait for redirect to dashboard
	time.Sleep(500 * time.Millisecond)

	// Verify we're logged in by checking URL contains dashboard
	currentURL := page.MustInfo().URL
	if !strings.Contains(currentURL, "/dashboard") {
		t.Fatalf("Expected to be on dashboard after signup, got: %s", currentURL)
	}

	return &TestUser{
		Username: username,
		Password: password,
		Page:     page,
		Context:  incognito,
	}
}

// signInUser signs in an existing user
func signInUser(t *testing.T, username, password string) *TestUser {
	page := browser.MustPage(testBaseURL + "/signin")

	// Wait for the form to be ready
	page.MustElement("#username").MustInput(username)
	page.MustElement("#password").MustInput(password)
	page.MustElement("button[type=submit]").MustClick()

	// Wait for the form submission and redirect to complete
	time.Sleep(500 * time.Millisecond)

	return &TestUser{
		Username: username,
		Password: password,
		Page:     page,
	}
}

// createPost creates a post with the given title and body
func (u *TestUser) createPost(t *testing.T, title, body string, publish bool) string {
	// Navigate to new post page
	u.Page.MustNavigate(testBaseURL + "/dashboard/post/new")

	// Wait for the title input to be visible (indicates page is ready)
	u.Page.Timeout(10 * time.Second).MustElement("#title")

	// Wait for JavaScript to fully initialize
	time.Sleep(500 * time.Millisecond)

	u.Page.MustElement("#title").MustInput(title)

	// Set the body via JavaScript since OverType editor is in use
	// Pass body as a parameter to avoid string escaping issues
	u.Page.MustEval(`(bodyVal) => { document.getElementById('body').value = bodyVal }`, body)

	if publish {
		checkbox := u.Page.MustElement("#published")
		if !checkbox.MustProperty("checked").Bool() {
			checkbox.MustClick()
		}
	}

	u.Page.MustElement("#submitButton").MustClick()

	// Wait for the redirect to complete
	time.Sleep(1 * time.Second)

	// The post edit page redirects to /dashboard/post/{id}, extract the slug from the page
	slug := u.Page.Timeout(10 * time.Second).MustElement("#slug").MustProperty("value").String()
	return slug
}

// navigateToSettings navigates to the settings page
func (u *TestUser) navigateToSettings(t *testing.T) {
	u.Page.MustNavigate(testBaseURL + "/dashboard/settings")
	time.Sleep(300 * time.Millisecond)
}

// navigateToPublicPost navigates to a public post
func (u *TestUser) navigateToPublicPost(t *testing.T, username, slug string) {
	u.Page.MustNavigate(fmt.Sprintf("%s/u/%s/%s", testBaseURL, username, slug))
	time.Sleep(300 * time.Millisecond)
}

// getPublicPage gets a new page (not authenticated) for viewing public content
func getPublicPage(t *testing.T) *rod.Page {
	page := browser.MustIncognito().MustPage(testBaseURL)
	time.Sleep(300 * time.Millisecond)
	return page
}

// cleanup removes the test database
func cleanup() {
	database.CloseDB()
	os.Remove("tests/" + testDBPath)
	os.Remove("tests/" + testDBPath + "-shm")
	os.Remove("tests/" + testDBPath + "-wal")
}

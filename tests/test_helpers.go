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
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

const (
	testPort    = "8888"
	testBaseURL = "http://localhost:" + testPort
	testDBPath  = "kitty_test.db"
)

var (
	testServer *http.Server
	browser    *rod.Browser
	testMutex  sync.Mutex // Ensure only one test runs at a time
)

// setupTestEnvironment initializes the test database and server
func setupTestEnvironment(t *testing.T) {
	// Lock mutex to ensure only one test runs at a time
	// This is needed because tests share global state (browser, server, database)
	testMutex.Lock()
	t.Cleanup(func() {
		testMutex.Unlock()
	})

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

	r.Route("/api", func(r chi.Router) {
		r.Route("/v1", func(r chi.Router) {
			r.Get("/get-user-posts-messages/{userID}", site.GetUserPostsMessagesAPI)
		})
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

// TestUser represents a test user with their own browser page
type TestUser struct {
	Username string
	Password string
	Page     *rod.Page
	Cookies  []*proto.NetworkCookieParam // Saved cookies for this user's session
}

// createTestUser creates a new user via the signup page
func createTestUser(t *testing.T, username, password string) *TestUser {
	// Create a new page for this user
	page := browser.MustPage()

	// Clear any existing cookies to ensure a fresh session
	page.MustSetCookies()

	// Navigate to signup page and wait for it to load
	page.MustNavigate(testBaseURL + "/signup")
	time.Sleep(500 * time.Millisecond)

	// Wait for the form elements to be ready and use JS input to avoid hanging
	usernameEl := page.MustElement("#username")
	usernameEl.MustEval(`(val) => { this.value = val; this.dispatchEvent(new Event('input', { bubbles: true })); }`, username)

	passwordEl := page.MustElement("#password")
	passwordEl.MustEval(`(val) => { this.value = val; this.dispatchEvent(new Event('input', { bubbles: true })); }`, password)

	// Use JavaScript click to avoid hanging
	page.MustEval(`() => document.querySelector('button[type=submit]').click()`)

	// Wait for navigation to complete after form submission
	time.Sleep(700 * time.Millisecond)

	// Verify we're logged in by checking URL contains dashboard
	currentURL := page.MustInfo().URL
	if !strings.Contains(currentURL, "/dashboard") {
		t.Fatalf("Expected to be on dashboard after signup, got: %s", currentURL)
	}

	// Save this user's cookies for later restoration
	cookies := page.MustCookies()
	cookieParams := convertCookiesToParams(cookies)

	return &TestUser{
		Username: username,
		Password: password,
		Page:     page,
		Cookies:  cookieParams,
	}
}

// restoreSession restores the user's session by setting their cookies
func (u *TestUser) restoreSession() {
	// Set the user's cookies to restore their session
	if len(u.Cookies) > 0 {
		u.Page.MustSetCookies(u.Cookies...)
	}
}

// signInUser signs in an existing user
func signInUser(t *testing.T, username, password string) *TestUser {
	page := browser.MustPage()

	// Clear any existing cookies
	page.MustSetCookies()

	page.MustNavigate(testBaseURL + "/signin")
	time.Sleep(500 * time.Millisecond)

	// Wait for the form to be ready and use JS input to avoid hanging
	usernameEl := page.MustElement("#username")
	usernameEl.MustEval(`(val) => { this.value = val; this.dispatchEvent(new Event('input', { bubbles: true })); }`, username)

	passwordEl := page.MustElement("#password")
	passwordEl.MustEval(`(val) => { this.value = val; this.dispatchEvent(new Event('input', { bubbles: true })); }`, password)

	// Use JavaScript click to avoid hanging
	page.MustEval(`() => document.querySelector('button[type=submit]').click()`)

	// Wait for navigation to complete
	time.Sleep(700 * time.Millisecond)

	cookies := page.MustCookies()
	cookieParams := convertCookiesToParams(cookies)

	return &TestUser{
		Username: username,
		Password: password,
		Page:     page,
		Cookies:  cookieParams,
	}
}

// convertCookiesToParams converts NetworkCookie to NetworkCookieParam
func convertCookiesToParams(cookies []*proto.NetworkCookie) []*proto.NetworkCookieParam {
	params := make([]*proto.NetworkCookieParam, len(cookies))
	for i, c := range cookies {
		params[i] = &proto.NetworkCookieParam{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
		}
	}
	return params
}

// createPost creates a post with the given title and body
func (u *TestUser) createPost(t *testing.T, title, body string, publish bool) string {
	// Restore session cookies before navigation
	u.restoreSession()

	// Navigate to new post page
	u.Page.MustNavigate(testBaseURL + "/dashboard/post/new")
	time.Sleep(1000 * time.Millisecond) // Wait for page load and JS to initialize

	// Verify we're on the right page
	currentURL := u.Page.MustInfo().URL
	if !strings.Contains(currentURL, "/dashboard/post/new") {
		t.Fatalf("Expected to be on /dashboard/post/new, got: %s", currentURL)
	}

	// Wait for elements with longer timeout
	titleEl := u.Page.Timeout(15 * time.Second).MustElement("#title")
	u.Page.Timeout(15 * time.Second).MustElement("#body")         // Verify body exists
	u.Page.Timeout(15 * time.Second).MustElement("#submitButton") // Verify submit button exists

	// Use JavaScript for input to avoid Rod's hanging MustInput method
	titleEl.MustEval(`(val) => { this.value = val; this.dispatchEvent(new Event('input', { bubbles: true })); }`, title)

	// Set the body via JavaScript since OverType editor is in use
	u.Page.MustEval(`(bodyVal) => { document.getElementById('body').value = bodyVal }`, body)

	if publish {
		// Use JavaScript to check the published checkbox
		u.Page.MustEval(`() => {
const cb = document.getElementById('published');
if (!cb.checked) cb.click();
}`)
	}

	// Use JavaScript for click to avoid Rod's hanging wait methods
	u.Page.MustEval(`() => document.getElementById('submitButton').click()`)

	// Wait for redirect to complete
	time.Sleep(700 * time.Millisecond)

	// Update cookies after the action
	u.Cookies = convertCookiesToParams(u.Page.MustCookies())

	// The post edit page redirects to /dashboard/post/{id}, extract the slug from the page
	slug := u.Page.Timeout(15 * time.Second).MustElement("#slug").MustProperty("value").String()
	return slug
}

// navigateToSettings navigates to the settings page
func (u *TestUser) navigateToSettings(t *testing.T) {
	u.restoreSession()
	u.Page.MustNavigate(testBaseURL + "/dashboard/settings")
	time.Sleep(500 * time.Millisecond)
}

// navigateToPublicPost navigates to a public post
func (u *TestUser) navigateToPublicPost(t *testing.T, username, slug string) {
	u.Page.MustNavigate(fmt.Sprintf("%s/u/%s/%s", testBaseURL, username, slug))
	time.Sleep(500 * time.Millisecond)
}

// getPublicPage gets a new page (not authenticated) for viewing public content
func getPublicPage(t *testing.T) *rod.Page {
	page := browser.MustPage()
	page.MustSetCookies() // Clear cookies to ensure not authenticated
	page.MustNavigate(testBaseURL)
	time.Sleep(500 * time.Millisecond)
	return page
}

// cleanup removes the test database
func cleanup() {
	database.CloseDB()
	os.Remove("tests/" + testDBPath)
	os.Remove("tests/" + testDBPath + "-shm")
	os.Remove("tests/" + testDBPath + "-wal")
}

package site

import (
	"context"
	"kitty/constants"
	"kitty/database"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
)

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

func TryPutUserInContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// try to set admin user into context
		cookie, err := r.Cookie(string(AuthenticatedUserTokenCookieName))
		if err != nil || cookie.Value == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Validate the token and retrieve the corresponding user
		var user database.AdminUser
		result := database.GetDB().Where(&database.AdminUser{SessionToken: cookie.Value}).First(&user)
		if result.Error != nil {
			// Clear the invalid cookie
			http.SetCookie(w, &http.Cookie{
				Name:     string(AuthenticatedUserTokenCookieName),
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   !constants.DEBUG_MODE,
				SameSite: http.SameSiteLaxMode,
			})
			next.ServeHTTP(w, r)
			return
		}

		// Store the admin user in the context
		ctx := context.WithValue(r.Context(), AuthenticatedUserCookieName, &user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func AuthProtectedMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// if logout then just continue
		if r.URL.Path == "/logout" {
			next.ServeHTTP(w, r)
			return
		}

		// check context for user
		adminUser := getSignedInUserOrNil(r)
		if adminUser == nil {
			http.Redirect(w, r, "/signin", http.StatusSeeOther)
			return
		}

		// try to set admin user into context
		cookie, err := r.Cookie(string(AuthenticatedUserTokenCookieName))
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/signin", http.StatusSeeOther)
			return
		}

		// otherwise, continue to the next handler
		next.ServeHTTP(w, r)
	})
}

// PlaintextCSRFMiddleware marks plaintext (non-TLS) requests so gorilla/csrf
// uses http scheme when performing same-origin comparison, avoiding
// false 'origin invalid' on local development over http.
func PlaintextCSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			r = csrf.PlaintextHTTPRequest(r)
		}
		next.ServeHTTP(w, r)
	})
}

// postContextKey is used to store the validated post in request context
type postContextKeyType struct{}

var postContextKey postContextKeyType

// PostOwnershipMiddleware validates that the current user owns the post specified
// by the {postID} URL parameter. If valid, it stores the post in the request context.
// Use getPostFromContext() in handlers to retrieve it.
func PostOwnershipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postID := chi.URLParam(r, "postID")
		if postID == "" {
			http.Error(w, "Post ID required", http.StatusBadRequest)
			return
		}

		var post database.Post
		result := database.GetDB().First(&post, postID)
		if result.Error != nil {
			http.Error(w, "Post not found", http.StatusNotFound)
			return
		}

		currentUser := getSignedInUserOrNil(r)
		if currentUser == nil || post.AdminUserID != currentUser.ID {
			http.Error(w, "You don't own this post", http.StatusUnauthorized)
			return
		}

		// Store post and user in context for handlers
		ctx := context.WithValue(r.Context(), postContextKey, &post)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getPostFromContext retrieves the post validated by PostOwnershipMiddleware.
// Returns nil if not present (middleware not applied or failed).
func getPostFromContext(r *http.Request) *database.Post {
	post, _ := r.Context().Value(postContextKey).(*database.Post)
	return post
}

// NoCacheForHTML adds strict no-cache headers for HTML responses to avoid
// serving stale CSRF-hidden-fields via intermediaries (e.g., CDN/proxy/browser).
// Applied conditionally for requests that accept HTML and are not assets/api.
func NoCacheForHTML(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")
		if strings.Contains(accept, "text/html") &&
			!strings.HasPrefix(r.URL.Path, "/assets/") &&
			!strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			w.Header().Add("Vary", "Cookie")
		}
		next.ServeHTTP(w, r)
	})
}

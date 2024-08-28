package site

import (
	"context"
	"kitty/database"
	"net/http"
	"strings"
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
				Name:   string(AuthenticatedUserTokenCookieName),
				Value:  "",
				Path:   "/",
				MaxAge: -1,
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

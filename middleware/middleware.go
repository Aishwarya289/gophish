package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	ctx "github.com/gophish/gophish/context"
	"github.com/gophish/gophish/models"
	"github.com/gorilla/csrf"
)

// CSRFExemptPrefixes are a list of routes that are exempt from CSRF protection
var CSRFExemptPrefixes = []string{
	"/api",
	"/login",
	"/logout",
	 "/reset_password",
}

// CSRFExceptions is middleware that skips CSRF protection for exempt routes
func CSRFExceptions(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, prefix := range CSRFExemptPrefixes {
			if strings.HasPrefix(r.URL.Path, prefix) {
				r = csrf.UnsafeSkipCheck(r)
				break
			}
		}
		handler.ServeHTTP(w, r)
	}
}

// Use stacks middleware functions for a handler
func Use(handler http.HandlerFunc, mid ...func(http.Handler) http.HandlerFunc) http.HandlerFunc {
	for _, m := range mid {
		handler = m(handler)
	}
	return handler
}

// GetContext attaches session and user context to each request
func GetContext(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing request", http.StatusInternalServerError)
			return
		}
		session, _ := Store.Get(r, "gophish")
		r = ctx.Set(r, "session", session)
		if id, ok := session.Values["id"]; ok {
			u, err := models.GetUser(id.(int64))
			if err != nil {
				r = ctx.Set(r, "user", nil)
			} else {
				r = ctx.Set(r, "user", u)
			}
		} else {
			r = ctx.Set(r, "user", nil)
		}
		handler.ServeHTTP(w, r)
		ctx.Clear(r)
	}
}

// RequireAPIKey validates an API key or Bearer token for secured routes
func RequireAPIKey(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Max-Age", "1000")
			w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
			return
		}
		r.ParseForm()
		ak := r.Form.Get("api_key")
		if ak == "" {
			tokens, ok := r.Header["Authorization"]
			if ok && len(tokens) >= 1 {
				ak = strings.TrimPrefix(tokens[0], "Bearer ")
			}
		}
		if ak == "" {
			JSONError(w, http.StatusUnauthorized, "API Key not set")
			return
		}
		u, err := models.GetUserByAPIKey(ak)
		if err != nil {
			JSONError(w, http.StatusUnauthorized, "Invalid API Key")
			return
		}
		r = ctx.Set(r, "user", u)
		r = ctx.Set(r, "user_id", u.Id)
		r = ctx.Set(r, "api_key", ak)
		handler.ServeHTTP(w, r)
	})
}

// RequireLogin ensures the user is authenticated, or redirects to login
func RequireLogin(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if u := ctx.Get(r, "user"); u != nil {
			currentUser := u.(models.User)
			if currentUser.PasswordChangeRequired && r.URL.Path != "/reset_password" {
				q := r.URL.Query()
				q.Set("next", r.URL.Path)
				http.Redirect(w, r, fmt.Sprintf("/reset_password?%s", q.Encode()), http.StatusTemporaryRedirect)
				return
			}
			handler.ServeHTTP(w, r)
			return
		}
		q := r.URL.Query()
		q.Set("next", r.URL.Path)
		http.Redirect(w, r, fmt.Sprintf("/login?%s", q.Encode()), http.StatusTemporaryRedirect)
	}
}

// EnforceViewOnly ensures edit access is restricted unless permitted
func EnforceViewOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			user := ctx.Get(r, "user").(models.User)
			access, err := user.HasPermission(models.PermissionModifyObjects)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if !access {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePermission checks if user has required permission
func RequirePermission(perm string) func(http.Handler) http.HandlerFunc {
	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user := ctx.Get(r, "user").(models.User)
			access, err := user.HasPermission(perm)
			if err != nil {
				JSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if !access {
				JSONError(w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
				return
			}
			next.ServeHTTP(w, r)
		}
	}
}

// ApplySecurityHeaders sets security-related HTTP headers
func ApplySecurityHeaders(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none';")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	}
}

// JSONError writes an error response in JSON format
func JSONError(w http.ResponseWriter, c int, m string) {
	cj, _ := json.MarshalIndent(models.Response{Success: false, Message: m}, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", cj)
}

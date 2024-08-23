package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"kitty/constants"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/datatypes"
)

type AdminCookieName string

const AuthenticatedUserCookieName = AdminCookieName("authenticated_user")
const AuthenticatedUserTokenCookieName = AdminCookieName("authenticated_user_token")

var templatesCache sync.Map

func renderTemplate(w http.ResponseWriter, r *http.Request, templateName string, data any) {
	type GlobalTemplateData struct {
		CurrentUser *AdminUser
		IsDebug     bool
	}

	templateData := struct {
		Global GlobalTemplateData
		Data   any
	}{
		Global: GlobalTemplateData{
			CurrentUser: getSignedInUserOrNil(r),
			IsDebug:     constants.DEBUG_MODE,
		},
		Data: data,
	}

	actualTemplate, ok := templatesCache.Load(templateName)
	if !ok || constants.DEBUG_MODE {

		templatesDir := "templates/"

		baseTemplate := template.New("layout.html").Funcs(template.FuncMap{
			"jsonListToCommaSeparated": func(jsonList datatypes.JSON) string {
				var tags []string
				err := json.Unmarshal(jsonList, &tags)
				if err != nil {
					log.Printf("Failed to parse JSON list: %v", err)
					return ""
				}
				for i, tag := range tags {
					tags[i] = strings.TrimSpace(tag)
				}
				return strings.Join(tags, ", ")
			},
		})

		baseTemplate = template.Must(baseTemplate.ParseFiles(filepath.Join(templatesDir, "layout.html")))
		actualTemplate = template.Must(baseTemplate.ParseFiles(filepath.Join(templatesDir, templateName+".html")))

		templatesCache.Store(templateName, actualTemplate)
	}

	err := actualTemplate.(*template.Template).Execute(w, templateData)

	if err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func getSignedInUserOrNil(r *http.Request) *AdminUser {
	adminUser, _ := r.Context().Value(AuthenticatedUserCookieName).(*AdminUser)
	return adminUser
}

func getSignedInUserOrFail(r *http.Request) *AdminUser {
	adminUser := getSignedInUserOrNil(r)
	if adminUser == nil {
		log.Fatalf("Expected user to be signed in but it wasn't")
	}

	return adminUser
}

func generateAuthToken() (string, error) {
	const tokenLength = 32
	tokenBytes := make([]byte, tokenLength)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	return token, nil
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// if logout then just continue
		if r.URL.Path == "/logout" {
			next.ServeHTTP(w, r)
			return
		}

		// try to set admin user into context
		cookie, err := r.Cookie(string(AuthenticatedUserTokenCookieName))
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/signin", http.StatusSeeOther)
			return
		}

		// Validate the token and retrieve the corresponding user
		var user AdminUser
		result := db.Where(&AdminUser{SessionToken: cookie.Value}).First(&user)
		if result.Error != nil {
			// Clear the invalid cookie
			http.SetCookie(w, &http.Cookie{
				Name:   string(AuthenticatedUserTokenCookieName),
				Value:  "",
				Path:   "/",
				MaxAge: -1,
			})

			http.Redirect(w, r, "/signin", http.StatusSeeOther)
			return
		}

		// Store the admin user in the context
		ctx := context.WithValue(r.Context(), AuthenticatedUserCookieName, &user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func userSignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		adminUser := getSignedInUserOrNil(r)
		if adminUser == nil {
			renderTemplate(w, r, "signin", nil)
			return
		} else {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}

	} else {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var admin AdminUser
		result := db.Where(&AdminUser{Username: username}).First(&admin)
		if result.Error != nil {
			http.Error(w, "Invalid username. You're trying to sign in, but perhaps you still need to sign up?", http.StatusUnauthorized)
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
		if err != nil {
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return
		}

		// Generate a new token for the session
		token, err := generateAuthToken()
		if err != nil {
			http.Error(w, "Error signing in", http.StatusInternalServerError)
			return
		}

		admin.SessionToken = token
		db.Save(&admin)

		http.SetCookie(w, &http.Cookie{
			Name:  string(AuthenticatedUserTokenCookieName),
			Value: token,
			Path:  "/",
		})

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func userSignUp(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		adminUser := getSignedInUserOrNil(r)
		if adminUser == nil {
			renderTemplate(w, r, "signup", nil)
			return
		} else {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}

	} else {
		username := r.FormValue("username")
		password := r.FormValue("password")

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error creating account: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Create a new token and store it in a cookie
		token, err := generateAuthToken()
		if err != nil {
			http.Error(w, "Error creating account: "+err.Error(), http.StatusInternalServerError)
			return
		}

		newAdmin := AdminUser{Username: username, PasswordHash: passwordHash, SessionToken: token}

		result := db.Create(&newAdmin)
		if result.Error != nil {
			http.Error(w, "Error creating account: "+result.Error.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  string(AuthenticatedUserTokenCookieName),
			Value: token,
			Path:  "/",
		})

		// Redirect to the admin sign-in page after successful sign-up
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func userLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   string(AuthenticatedUserTokenCookieName),
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/signin", http.StatusSeeOther)
}

func userPostList(w http.ResponseWriter, r *http.Request) {
	adminUser := getSignedInUserOrFail(r)

	var posts []Post
	result := db.Where(&Post{AdminUserID: adminUser.ID}).Find(&posts)
	if result.Error != nil {
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, r, "dashboard/list_posts", posts)
}

func buildPostFromFormRequest(r *http.Request) (Post, error) {
	adminUser := getSignedInUserOrNil(r)
	if adminUser == nil {
		return Post{}, errors.New("user not signed in")
	}

	title := r.FormValue("title")
	body := r.FormValue("body")
	link := r.FormValue("link")
	publishedDate, _ := time.Parse(time.RFC3339, r.FormValue("publishedDate"))
	isPage := r.FormValue("isPage") == "on"
	metaDescription := r.FormValue("metaDescription")
	metaImage := r.FormValue("metaImage")
	lang := r.FormValue("lang")
	tags := r.FormValue("tags")
	makeDiscoverable := r.FormValue("makeDiscoverable") == "on"

	tagsJSON, err := json.Marshal(strings.Split(tags, ","))
	if err != nil {
		return Post{}, errors.New("failed to parse post tags")
	}

	newPost := Post{
		AdminUserID:      adminUser.ID,
		Title:            title,
		Body:             body,
		Link:             link,
		PublishedDate:    publishedDate,
		IsPage:           isPage,
		MetaDescription:  metaDescription,
		MetaImage:        metaImage,
		Lang:             lang,
		Tags:             datatypes.JSON(tagsJSON),
		MakeDiscoverable: makeDiscoverable,
	}

	return newPost, nil
}

func createPost(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		renderTemplate(w, r, "dashboard/create_edit_post", nil)
	case "POST":
		newPost, e := buildPostFromFormRequest(r)
		if e != nil {
			http.Error(w, "Error creating post: "+e.Error(), http.StatusInternalServerError)
			return
		}

		result := db.Create(&newPost)
		if result.Error != nil {
			http.Error(w, "Error creating post", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/dashboard/post/"+strconv.Itoa(int(newPost.ID)), http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func editPost(w http.ResponseWriter, r *http.Request) {
	postID := chi.URLParam(r, "postID")

	var post Post
	result := db.First(&post, postID)
	if result.Error != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	currentUser := getSignedInUserOrFail(r)
	if post.AdminUserID != currentUser.ID {
		http.Error(w, "You don't own this post", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case "GET":
		renderTemplate(w, r, "dashboard/create_edit_post", post)

	case "POST":
		newPostData, e := buildPostFromFormRequest(r)
		if e != nil {
			http.Error(w, "Error updating post: "+e.Error(), http.StatusInternalServerError)
			return
		}

		post.Title = newPostData.Title
		post.Body = newPostData.Body
		post.Link = newPostData.Link
		post.PublishedDate = newPostData.PublishedDate
		post.IsPage = newPostData.IsPage
		post.MetaDescription = newPostData.MetaDescription
		post.MetaImage = newPostData.MetaImage
		post.Lang = newPostData.Lang
		post.Tags = newPostData.Tags
		post.MakeDiscoverable = newPostData.MakeDiscoverable

		result = db.Save(&post)
		if result.Error != nil {
			http.Error(w, "Error updating guestbook", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/dashboard/post/"+postID, http.StatusOK)

	case "DELETE":
		result = db.Delete(&post)
		if result.Error != nil {
			http.Error(w, "Error deleting post", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func publicViewPost(w http.ResponseWriter, r *http.Request) {
	postID := chi.URLParam(r, "postID")

	var post Post
	result := db.First(&post, postID)
	if result.Error != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	renderTemplate(w, r, "public_view_post", post)
}

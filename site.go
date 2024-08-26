package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"github.com/gosimple/slug"
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
		SiteName    string
		PublicURL   string
	}

	templateData := struct {
		Global GlobalTemplateData
		Data   any
	}{
		Global: GlobalTemplateData{
			CurrentUser: getSignedInUserOrNil(r),
			IsDebug:     constants.DEBUG_MODE,
			SiteName:    constants.APP_NAME,
			PublicURL:   constants.PUBLIC_URL,
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
			"parseMarkdown": func(markdownStr string) template.HTML {
				extensions := parser.CommonExtensions | parser.AutoHeadingIDs
				p := parser.NewWithExtensions(extensions)
				doc := p.Parse([]byte(markdownStr))

				// create HTML renderer with extensions
				htmlFlags := html.CommonFlags | html.HrefTargetBlank
				opts := html.RendererOptions{Flags: htmlFlags}
				renderer := html.NewRenderer(opts)

				rendered := markdown.Render(doc, renderer)

				return template.HTML(rendered)
			},
			"dateFmt": func(layout string, t time.Time) string {
				return t.Format(layout)
			},
			"now": func() time.Time {
				return time.Now()
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

func TryPutUserInContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// try to set admin user into context
		cookie, err := r.Cookie(string(AuthenticatedUserTokenCookieName))
		if err != nil || cookie.Value == "" {
			next.ServeHTTP(w, r)
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
	result := db.Where(&Post{AdminUserID: adminUser.ID}).Order("published_date DESC").Find(&posts)
	if result.Error != nil {
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, r, "dashboard/list_posts", posts)
}

func importPosts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		renderTemplate(w, r, "dashboard/import_posts", nil)
	case "POST":
		importType := r.FormValue("import_type")
		if importType != "bearblog" {
			http.Error(w, "Only BearBlog imports are supported. The import type you specified is not supported: "+importType, http.StatusBadRequest)
			return
		}

		user := getSignedInUserOrFail(r)
		allCurrentPosts := make(map[string]Post)

		// Retrieve all current posts
		var existingPosts []Post
		result := db.Find(&existingPosts)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve posts: "+result.Error.Error(), http.StatusInternalServerError)
			return
		}

		// Populate the map with slugs as keys and Post instances as values
		for _, post := range existingPosts {
			allCurrentPosts[post.Title] = post
		}

		overwriteExisting := r.FormValue("overwrite_existing") == "on"

		// Parse the multipart form data
		err := r.ParseMultipartForm(10 << 20) // Limit your max memory usage
		if err != nil {
			http.Error(w, "Failed to parse multipart form data: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Retrieve the file from the form data
		file, _, err := r.FormFile("bear_export")
		if err != nil {
			http.Error(w, "Failed to retrieve file: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Parse the CSV file
		reader := csv.NewReader(file)

		// Read the header row
		_, err = reader.Read()
		if err != nil {
			http.Error(w, "Failed to read CSV header: "+err.Error(), http.StatusBadRequest)
			return
		}

		records, err := reader.ReadAll()
		if err != nil {
			http.Error(w, "Failed to parse CSV file: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Convert CSV records to Post structs
		var incomingPosts []Post
		for _, record := range records {
			if len(record) < 2 {
				http.Error(w, "Invalid CSV format", http.StatusBadRequest)
				return
			}

			slug := slug.Make(record[4])
			if _, exists := allCurrentPosts[slug]; exists {
				if overwriteExisting {
					// Delete the existing post
					result := db.Delete(allCurrentPosts[slug])
					if result.Error != nil {
						http.Error(w, "Failed to delete existing post: "+result.Error.Error(), http.StatusInternalServerError)
						return
					}

					// Remove the post from the map
					delete(allCurrentPosts, slug)
				} else {
					// Skip this post
					continue
				}
			}

			publishedDate, err := tryParseDate(record[6])
			if err != nil {
				http.Error(w, "Failed to parse date: "+err.Error(), http.StatusBadRequest)
				return
			}

			var tags datatypes.JSON
			err = json.Unmarshal([]byte(record[8]), &tags)
			if err != nil {
				http.Error(w, "Failed to parse tags JSON: "+err.Error(), http.StatusBadRequest)
				return
			}

			lang := "en"
			if record[16] != "" {
				lang = record[16]
			}

			post := Post{
				Title:           record[3],
				Slug:            slug,
				PublishedDate:   publishedDate,
				Tags:            tags,
				Published:       record[9] == "TRUE" || record[9] == "true" || record[9] == "True",
				IsPage:          record[11] == "TRUE" || record[11] == "true" || record[11] == "True",
				Body:            record[12],
				MetaDescription: record[14],
				MetaImage:       record[15],
				Lang:            lang,
				AdminUserID:     user.ID,
			}
			incomingPosts = append(incomingPosts, post)
		}

		// Insert the posts into the database
		for _, post := range incomingPosts {
			result := db.Create(&post)
			if result.Error != nil {
				http.Error(w, "Failed to insert post: "+result.Error.Error(), http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func tryParseDate(dateStr string) (time.Time, error) {
	formats := []string{
		"2006-01-02T15:04",
		time.RFC3339,
		time.RFC3339Nano,
		time.RFC1123,
		time.RFC1123Z,
		time.RFC822,
		time.RFC822Z,
		time.RFC850,
		time.ANSIC,
		time.UnixDate,
		time.RubyDate,
		// custom formats
		"Mon Jan 2 03:04:05 PM MST 2006",
		"2006-01-02 15:04:05-07:00",
	}

	for _, layout := range formats {
		date, err := time.Parse(layout, dateStr)
		if err == nil {
			return date, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

func buildPostFromFormRequest(r *http.Request) (Post, error) {
	adminUser := getSignedInUserOrNil(r)
	if adminUser == nil {
		return Post{}, errors.New("user not signed in")
	}

	title := r.FormValue("title")
	body := r.FormValue("body")
	slug := r.FormValue("slug")
	publishedDate, _ := tryParseDate(r.FormValue("publishedDate"))
	isPage := r.FormValue("isPage") == "on"
	metaDescription := r.FormValue("metaDescription")
	metaImage := r.FormValue("metaImage")
	lang := r.FormValue("lang")
	tags := r.FormValue("tags")
	published := r.FormValue("published") == "on"

	tagsJSON, err := json.Marshal(strings.Split(tags, ","))
	if err != nil {
		return Post{}, errors.New("failed to parse post tags")
	}

	newPost := Post{
		AdminUserID:     adminUser.ID,
		Title:           title,
		Body:            body,
		Slug:            slug,
		PublishedDate:   publishedDate,
		IsPage:          isPage,
		MetaDescription: metaDescription,
		MetaImage:       metaImage,
		Lang:            lang,
		Tags:            datatypes.JSON(tagsJSON),
		Published:       published,
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

		if newPost.Slug == "" {
			newPost.Slug = slug.Make(newPost.Title)
		}

		existingSlugPost, err := getPostWithSlug(newPost.Slug)
		if err != nil {
			http.Error(w, "Error verifying if posts exists: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if existingSlugPost != nil {
			http.Error(w, "A post with the same slug already exists", http.StatusBadRequest)
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

		post.Slug = newPostData.Slug
		if post.Slug == "" {
			post.Slug = slug.Make(post.Title)
		}

		post.PublishedDate = newPostData.PublishedDate
		post.IsPage = newPostData.IsPage
		post.MetaDescription = newPostData.MetaDescription
		post.MetaImage = newPostData.MetaImage
		post.Lang = newPostData.Lang
		post.Tags = newPostData.Tags
		post.Published = newPostData.Published

		result = db.Save(&post)
		if result.Error != nil {
			http.Error(w, "Error updating guestbook", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/dashboard/post/"+postID, http.StatusSeeOther)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func deletePost(w http.ResponseWriter, r *http.Request) {
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
	case "POST":
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

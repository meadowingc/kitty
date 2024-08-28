package site

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"kitty/constants"
	"kitty/database"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gosimple/slug"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func UserSignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		adminUser := getSignedInUserOrNil(r)
		if adminUser == nil {
			RenderTemplate(w, r, "signin", nil)
			return
		} else {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}

	} else {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var admin database.AdminUser
		result := database.GetDB().Where(&database.AdminUser{Username: username}).First(&admin)
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
		database.GetDB().Save(&admin)

		http.SetCookie(w, &http.Cookie{
			Name:  string(AuthenticatedUserTokenCookieName),
			Value: token,
			Path:  "/",
		})

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func UserSignUp(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		adminUser := getSignedInUserOrNil(r)
		if adminUser == nil {
			RenderTemplate(w, r, "signup", nil)
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

		newAdmin := database.AdminUser{Username: username, PasswordHash: passwordHash, SessionToken: token}

		result := database.GetDB().Create(&newAdmin)
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

func UserLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   string(AuthenticatedUserTokenCookieName),
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/signin", http.StatusSeeOther)
}

func UserPostList(w http.ResponseWriter, r *http.Request) {
	adminUser := getSignedInUserOrFail(r)

	var posts []database.Post
	result := database.GetDB().Where(&database.Post{AdminUserID: adminUser.ID}).Order("published_date DESC").Find(&posts)
	if result.Error != nil {
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}

	RenderTemplate(w, r, "dashboard/list_posts", posts)
}

func ImportPosts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		RenderTemplate(w, r, "dashboard/import_posts", nil)
	case "POST":
		importType := r.FormValue("import_type")
		if importType != "bearblog" {
			http.Error(w, "Only BearBlog imports are supported. The import type you specified is not supported: "+importType, http.StatusBadRequest)
			return
		}

		user := getSignedInUserOrFail(r)
		allCurrentPosts := make(map[string]database.Post)

		// Retrieve all current posts
		var existingPosts []database.Post
		result := database.GetDB().Find(&existingPosts)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve posts: "+result.Error.Error(), http.StatusInternalServerError)
			return
		}

		// Populate the map with slugs as keys and Post instances as values
		for _, post := range existingPosts {
			allCurrentPosts[post.Slug] = post
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
		var incomingPosts []database.Post
		for _, record := range records {
			if len(record) < 2 {
				http.Error(w, "Invalid CSV format", http.StatusBadRequest)
				return
			}

			slug := slug.Make(record[4])
			if existingPost, exists := allCurrentPosts[slug]; exists {
				if overwriteExisting {
					// Delete the existing post
					result := database.GetDB().Delete(&existingPost)
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

			title := record[3]
			body := record[12]
			if len(body) > constants.MAX_POST_LENGTH {
				http.Error(w, fmt.Sprintf(
					"Failed to import post with title '%s': post body too long. It must be less than '%d' characters, but it is '%d' characters long",
					title, constants.MAX_POST_LENGTH, len(body)), http.StatusBadRequest)
				return
			}

			post := database.Post{
				Title:           title,
				Slug:            slug,
				PublishedDate:   publishedDate,
				Tags:            tags,
				Published:       record[9] == "TRUE" || record[9] == "true" || record[9] == "True",
				IsPage:          record[11] == "TRUE" || record[11] == "true" || record[11] == "True",
				Body:            body,
				MetaDescription: record[14],
				MetaImage:       record[15],
				Lang:            lang,
				AdminUserID:     user.ID,
			}
			incomingPosts = append(incomingPosts, post)
		}

		// Insert the posts into the database
		for _, post := range incomingPosts {
			result := database.GetDB().Create(&post)
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

func CreatePost(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		RenderTemplate(w, r, "dashboard/create_edit_post", nil)
	case "POST":
		newPost, e := buildPostFromFormRequest(r)
		if e != nil {
			http.Error(w, "Error creating post: "+e.Error(), http.StatusInternalServerError)
			return
		}

		if newPost.Slug == "" {
			newPost.Slug = slug.Make(newPost.Title)
		}

		existingSlugPost, err := database.GetPostWithSlug(newPost.Slug)
		if err != nil {
			http.Error(w, "Error verifying if posts exists: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if existingSlugPost != nil {
			http.Error(w, "A post with the same slug already exists", http.StatusBadRequest)
			return
		}

		result := database.GetDB().Create(&newPost)
		if result.Error != nil {
			http.Error(w, "Error creating post", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/dashboard/post/"+strconv.Itoa(int(newPost.ID)), http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func UpdatePost(w http.ResponseWriter, r *http.Request) {
	postID := chi.URLParam(r, "postID")

	var post database.Post
	result := database.GetDB().First(&post, postID)
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
		RenderTemplate(w, r, "dashboard/create_edit_post", post)

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

		existingSlugPost, err := database.GetPostWithSlug(post.Slug)
		if err != nil {
			http.Error(w, "Error verifying if posts exists: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if existingSlugPost != nil && existingSlugPost.ID != post.ID {
			http.Error(w, "A post with the same slug already exists", http.StatusBadRequest)
			return
		}

		post.PublishedDate = newPostData.PublishedDate
		post.IsPage = newPostData.IsPage
		post.MetaDescription = newPostData.MetaDescription
		post.MetaImage = newPostData.MetaImage
		post.Lang = newPostData.Lang
		post.Tags = newPostData.Tags
		post.Published = newPostData.Published

		result = database.GetDB().Save(&post)
		if result.Error != nil {
			http.Error(w, "Error updating guestbook", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/dashboard/post/"+postID, http.StatusSeeOther)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func DeletePost(w http.ResponseWriter, r *http.Request) {
	postID := chi.URLParam(r, "postID")

	var post database.Post
	result := database.GetDB().First(&post, postID)
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
		result = database.GetDB().Delete(&post)
		if result.Error != nil {
			http.Error(w, "Error deleting post", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func PublicViewPost(w http.ResponseWriter, r *http.Request) {
	postID := chi.URLParam(r, "postID")

	var post database.Post
	result := database.GetDB().First(&post, postID)
	if result.Error != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	RenderTemplate(w, r, "public_view_post", post)
}

func PublicViewUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")

	var user database.AdminUser
	result := database.GetDB().Preload("Posts", func(db *gorm.DB) *gorm.DB {
		return db.Select("id, title, admin_user_id", "published_date").Where("published = ?", true).Order("published_date DESC")
	}).First(&user, userID)
	if result.Error != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	RenderTemplate(w, r, "public_view_user", user)
}

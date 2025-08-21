package site

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"kitty/constants"
	"kitty/database"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gosimple/slug"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/datatypes"
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
			Name:     string(AuthenticatedUserTokenCookieName),
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   !constants.DEBUG_MODE,
			SameSite: http.SameSiteLaxMode,
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
			Name:     string(AuthenticatedUserTokenCookieName),
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   !constants.DEBUG_MODE,
			SameSite: http.SameSiteLaxMode,
		})

		// Redirect to the admin sign-in page after successful sign-up
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func UserLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     string(AuthenticatedUserTokenCookieName),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !constants.DEBUG_MODE,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/signin", http.StatusSeeOther)
}

func UserDashboardHome(w http.ResponseWriter, r *http.Request) {
	adminUser := getSignedInUserOrFail(r)

	var posts []database.Post
	result := database.GetDB().Where(&database.Post{
		AdminUserID: adminUser.ID,
	}).Order("published_date DESC").Find(&posts)
	if result.Error != nil {
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}

	postsOnly := make([]database.Post, 0, len(posts))
	pagesOnly := make([]database.Post, 0, len(posts))
	for _, p := range posts {
		if p.IsPage {
			pagesOnly = append(pagesOnly, p)
		} else {
			postsOnly = append(postsOnly, p)
		}
	}

	data := struct {
		All   []database.Post
		Posts []database.Post
		Pages []database.Post
	}{
		All:   posts,
		Posts: postsOnly,
		Pages: pagesOnly,
	}

	RenderTemplate(w, r, "dashboard/dashboard", data)
}

func UserPostList(w http.ResponseWriter, r *http.Request) {
	adminUser := getSignedInUserOrFail(r)

	var posts []database.Post
	result := database.GetDB().Where(&database.Post{
		AdminUserID: adminUser.ID,
	}).Order("published_date DESC").Find(&posts)
	if result.Error != nil {
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}

	filteredPosts := make([]database.Post, 0)
	for _, post := range posts {
		if !post.IsPage {
			filteredPosts = append(filteredPosts, post)
		}
	}

	var data = struct {
		Posts  []database.Post
		IsPage bool
	}{
		Posts:  filteredPosts,
		IsPage: false,
	}

	RenderTemplate(w, r, "dashboard/list_posts_and_pages", data)
}

func UserPageList(w http.ResponseWriter, r *http.Request) {
	adminUser := getSignedInUserOrFail(r)

	var pages []database.Post
	result := database.GetDB().Where(&database.Post{
		AdminUserID: adminUser.ID,
	}).Order("published_date DESC").Find(&pages)
	if result.Error != nil {
		http.Error(w, "Error fetching pages", http.StatusInternalServerError)
		return
	}

	filteredPages := make([]database.Post, 0)
	for _, page := range pages {
		if page.IsPage {
			filteredPages = append(filteredPages, page)
		}
	}

	var data = struct {
		Posts  []database.Post
		IsPage bool
	}{
		Posts:  filteredPages,
		IsPage: true,
	}

	RenderTemplate(w, r, "dashboard/list_posts_and_pages", data)
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
		result := database.GetDB().Where(&database.Post{AdminUserID: user.ID}).Find(&existingPosts)
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
				ShowOnHomepage:  !(record[11] == "TRUE" || record[11] == "true" || record[11] == "True"),
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

type createEditData struct {
	database.Post
	TagSuggestions []string
}

func collectUserTags(userID uint) []string {
	var posts []database.Post
	database.GetDB().Where("admin_user_id = ?", userID).Select("tags").Find(&posts)
	seen := map[string]struct{}{}
	for _, p := range posts {
		var tags []string
		if err := json.Unmarshal(p.Tags, &tags); err == nil {
			for _, t := range tags {
				tag := strings.TrimSpace(t)
				if tag != "" {
					if _, ok := seen[tag]; !ok {
						seen[tag] = struct{}{}
					}
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for tag := range seen {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func CreatePost(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		user := getSignedInUserOrFail(r)
		data := createEditData{
			TagSuggestions: collectUserTags(user.ID),
		}
		RenderTemplate(w, r, "dashboard/create_edit_post", data)
	case "POST":
		newPost, e := buildPostFromFormRequest(r)
		if e != nil {
			http.Error(w, "Error creating post: "+e.Error(), http.StatusInternalServerError)
			return
		}

		if newPost.Slug == "" {
			newPost.Slug = slug.Make(newPost.Title)
		}

		existingSlugPost, err := database.GetPostWithSlugForUser(newPost.AdminUserID, newPost.Slug)
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
		data := createEditData{
			Post:           post,
			TagSuggestions: collectUserTags(currentUser.ID),
		}
		RenderTemplate(w, r, "dashboard/create_edit_post", data)

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
		post.ShowOnHomepage = r.FormValue("showOnHomepage") == "on"

		existingSlugPost, err := database.GetPostWithSlugForUser(currentUser.ID, post.Slug)
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
		// clear homepage pointer if it pointed to this post
		if currentUser.HomePagePostID != nil && *currentUser.HomePagePostID == post.ID {
			currentUser.HomePagePostID = nil
			_ = database.GetDB().Save(currentUser)
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

	var user database.AdminUser
	if err := database.GetDB().First(&user, post.AdminUserID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	http.Redirect(w, r, "/u/"+url.PathEscape(user.Username)+"/"+url.PathEscape(post.Slug), http.StatusMovedPermanently)
}

func PublicViewUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")

	var user database.AdminUser
	if err := database.GetDB().First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	http.Redirect(w, r, "/u/"+url.PathEscape(user.Username), http.StatusMovedPermanently)
}

func PublicViewPostBySlug(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	slug := chi.URLParam(r, "slug")

	var admin database.AdminUser
	if err := database.GetDB().Where("username = ?", username).First(&admin).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	var post database.Post
	if err := database.GetDB().Where("slug = ? AND admin_user_id = ?", slug, admin.ID).First(&post).Error; err != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	viewer := getSignedInUserOrNil(r)
	if !post.Published {
		if viewer == nil || viewer.ID != admin.ID {
			http.Error(w, "Post not found", http.StatusNotFound)
			return
		}
	}

	// set viewing user context so templates can show blog title / header markdown
	r = setViewingUserInContext(r, &admin)

	RenderTemplate(w, r, "public_view_post", post)
}

func PublicViewUserByUsername(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	var user database.AdminUser
	result := database.GetDB().Where("username = ?", username).First(&user)
	if result.Error != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// always set viewing user context (for header markdown & blog title)
	r = setViewingUserInContext(r, &user)

	// if homepage post configured, attempt to render it
	if user.HomePagePostID != nil {
		var homePost database.Post
		pr := database.GetDB().Where("id = ? AND admin_user_id = ? AND published = ? AND is_page = ?", *user.HomePagePostID, user.ID, true, true).First(&homePost)
		if pr.Error == nil {
			RenderTemplate(w, r, "public_view_post", homePost)
			return
		} else {
			// clear invalid pointer
			user.HomePagePostID = nil
			_ = database.GetDB().Save(&user)
		}
	}

	PublicViewUserArchive(w, r)
}

// Dashboard settings: blog title, header markdown, homepage page selection
func UserSettings(w http.ResponseWriter, r *http.Request) {
	user := getSignedInUserOrFail(r)

	switch r.Method {
	case "GET":
		// fetch published pages to populate dropdown
		var pages []database.Post
		database.GetDB().Where("admin_user_id = ? AND published = ? AND is_page = ?", user.ID, true, true).Order("title ASC").Find(&pages)
		data := struct {
			User  *database.AdminUser
			Pages []database.Post
		}{User: user, Pages: pages}
		RenderTemplate(w, r, "dashboard/settings", data)
	case "POST":
		// parse form fields
		blogTitle := strings.TrimSpace(r.FormValue("blogTitle"))
		headerMarkdown := r.FormValue("headerMarkdown")
		homePagePostIDStr := strings.TrimSpace(r.FormValue("homePagePostID"))
		emoji := strings.TrimSpace(r.FormValue("emoji"))

		if len(blogTitle) > 120 {
			http.Error(w, "Blog title too long (max 120 chars)", http.StatusBadRequest)
			return
		}
		if len(headerMarkdown) > 8000 {
			http.Error(w, "Header markdown too long (max 8000 chars)", http.StatusBadRequest)
			return
		}

		// update fields
		user.BlogTitle = blogTitle
		user.HeaderMarkdown = headerMarkdown
		if len(emoji) > 16 {
			http.Error(w, "Emoji too long (max 16 chars)", http.StatusBadRequest)
			return
		}
		user.Emoji = emoji

		if homePagePostIDStr == "" {
			user.HomePagePostID = nil
		} else {
			id64, err := strconv.ParseUint(homePagePostIDStr, 10, 64)
			if err != nil {
				http.Error(w, "Invalid homepage page id", http.StatusBadRequest)
				return
			}
			var page database.Post
			pr := database.GetDB().Where("id = ? AND admin_user_id = ? AND published = ? AND is_page = ?", uint(id64), user.ID, true, true).First(&page)
			if pr.Error != nil {
				http.Error(w, "Selected homepage page invalid", http.StatusBadRequest)
				return
			}
			uid := uint(id64)
			user.HomePagePostID = &uid
		}

		if err := database.GetDB().Save(user).Error; err != nil {
			http.Error(w, "Failed saving settings: "+err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/dashboard/settings", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// RSS feed for a user's published posts
func PublicUserRSSFeed(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	var user database.AdminUser
	if err := database.GetDB().Where("username = ?", username).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	var posts []database.Post
	database.GetDB().Where("admin_user_id = ? AND published = ? AND is_page = ?", user.ID, true, false).
		Order("published_date DESC").Limit(25).Find(&posts)

	// set viewing context (for title usage maybe)
	r = setViewingUserInContext(r, &user)

	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	siteTitle := user.BlogTitle
	if strings.TrimSpace(siteTitle) == "" {
		siteTitle = user.Username
	}
	fmt.Fprintf(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	fmt.Fprintf(w, "<rss version=\"2.0\"><channel>\n")
	fmt.Fprintf(w, "<title>%s</title>\n", templateEscapeXML(siteTitle))
	fmt.Fprintf(w, "<link>%s/u/%s</link>\n", constants.PUBLIC_URL, url.PathEscape(user.Username))
	fmt.Fprintf(w, "<description>%s's posts</description>\n", templateEscapeXML(user.Username))
	now := time.Now().UTC().Format(time.RFC1123Z)
	fmt.Fprintf(w, "<lastBuildDate>%s</lastBuildDate>\n", now)

	for _, p := range posts {
		postURL := fmt.Sprintf("%s/u/%s/%s", constants.PUBLIC_URL, url.PathEscape(user.Username), url.PathEscape(p.Slug))
		pubDate := p.PublishedDate.UTC().Format(time.RFC1123Z)
		fmt.Fprintf(w, "<item><title>%s</title><link>%s</link><guid>%s</guid><pubDate>%s</pubDate></item>\n",
			templateEscapeXML(p.Title), postURL, postURL, pubDate)
	}

	fmt.Fprintf(w, "</channel></rss>")
}

// Tag page listing
func PublicViewUserTag(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	tag := chi.URLParam(r, "tag")

	var user database.AdminUser
	if err := database.GetDB().Where("username = ?", username).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// viewing context
	r = setViewingUserInContext(r, &user)

	// load all published posts then filter
	var posts []database.Post
	database.GetDB().Where("admin_user_id = ? AND published = ?", user.ID, true).Order("published_date DESC").Find(&posts)

	matched := make([]database.Post, 0)
	lowerTag := strings.ToLower(tag)
	for _, p := range posts {
		var tagList []string
		if err := json.Unmarshal(p.Tags, &tagList); err == nil {
			for _, t := range tagList {
				if strings.ToLower(strings.TrimSpace(t)) == lowerTag {
					matched = append(matched, p)
					break
				}
			}
		}
	}

	data := struct {
		Username string
		Tag      string
		Posts    []database.Post
	}{
		Username: user.Username,
		Tag:      tag,
		Posts:    matched,
	}

	RenderTemplate(w, r, "public_user_tag", data)
}

// Archive page listing all published posts (non-pages) grouped by year
func PublicViewUserArchive(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	var user database.AdminUser
	if err := database.GetDB().Where("username = ?", username).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// viewing context
	r = setViewingUserInContext(r, &user)

	// load all published non-page posts
	var posts []database.Post
	database.GetDB().Where("admin_user_id = ? AND published = ? AND is_page = ?", user.ID, true, false).
		Order("published_date DESC").
		Limit(constants.ARCHIVE_MAX_POSTS).
		Find(&posts)

	// group by year
	type YearGroup struct {
		Year  int
		Posts []database.Post
	}
	yearMap := map[int][]database.Post{}
	for _, p := range posts {
		y := p.PublishedDate.Year()
		yearMap[y] = append(yearMap[y], p)
	}
	years := make([]int, 0, len(yearMap))
	for y := range yearMap {
		years = append(years, y)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(years)))

	groups := make([]YearGroup, 0, len(years))
	for _, y := range years {
		groups = append(groups, YearGroup{Year: y, Posts: yearMap[y]})
	}

	data := struct {
		Username   string
		YearGroups []YearGroup
	}{
		Username:   user.Username,
		YearGroups: groups,
	}

	RenderTemplate(w, r, "public_user_archive", data)
}

func UserDeleteAccount(w http.ResponseWriter, r *http.Request) {
	user := getSignedInUserOrFail(r)
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	confirm := strings.TrimSpace(r.FormValue("confirm"))
	if confirm != user.Username {
		http.Error(w, "Confirmation text does not match your username", http.StatusBadRequest)
		return
	}
	if err := database.DeleteUserAndPosts(user.ID); err != nil {
		http.Error(w, "Error deleting account: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// clear auth cookie
	http.SetCookie(w, &http.Cookie{
		Name:     string(AuthenticatedUserTokenCookieName),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !constants.DEBUG_MODE,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/signin", http.StatusSeeOther)
}

// helper to escape basic XML entities for RSS feed generation
func templateEscapeXML(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

package site

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"kitty/constants"
	"kitty/database"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gorm.io/datatypes"
)

type AdminCookieName string

const AuthenticatedUserCookieName = AdminCookieName("authenticated_user")
const AuthenticatedUserTokenCookieName = AdminCookieName("authenticated_user_token")

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

func buildPostFromFormRequest(r *http.Request) (database.Post, error) {
	adminUser := getSignedInUserOrNil(r)
	if adminUser == nil {
		return database.Post{}, errors.New("user not signed in")
	}

	title := r.FormValue("title")
	body := r.FormValue("body")

	if len(body) > constants.MAX_POST_LENGTH {
		return database.Post{}, errors.New("post body too long. It must be less than " + strconv.Itoa(constants.MAX_POST_LENGTH) + " characters")
	}

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
		return database.Post{}, errors.New("failed to parse post tags")
	}

	newPost := database.Post{
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

func getSignedInUserOrNil(r *http.Request) *database.AdminUser {
	adminUser, _ := r.Context().Value(AuthenticatedUserCookieName).(*database.AdminUser)
	return adminUser
}

func getSignedInUserOrFail(r *http.Request) *database.AdminUser {
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

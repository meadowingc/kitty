package site

import (
	"kitty/constants"
	"kitty/database"
	"regexp"
	"strings"
)

// Regex to match markdown links: [text](url)
var markdownLinkRe = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)

// ExtractAndSaveBacklinks parses the post body for internal links and saves backlinks
func ExtractAndSaveBacklinks(post *database.Post) error {
	targetPostIDs := extractInternalLinkPostIDs(post.Body)
	return database.SaveBacklinksForPost(post.ID, targetPostIDs)
}

// extractInternalLinkPostIDs finds all internal Kitty links in markdown content
// and returns the post IDs they point to
func extractInternalLinkPostIDs(markdown string) []uint {
	matches := markdownLinkRe.FindAllStringSubmatch(markdown, -1)
	postIDs := make([]uint, 0)
	seen := make(map[uint]bool)

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		url := strings.TrimSpace(match[2])

		// Parse the URL to extract username and slug
		username, slug := parseInternalURL(url)
		if username == "" || slug == "" {
			continue
		}

		// Look up the post
		post, err := database.GetPostByUsernameAndSlug(username, slug)
		if err != nil || post == nil {
			continue
		}

		// Add to list if not already seen
		if !seen[post.ID] {
			seen[post.ID] = true
			postIDs = append(postIDs, post.ID)
		}
	}

	return postIDs
}

// parseInternalURL extracts username and slug from various internal URL formats:
// - /u/username/slug
// - https://kitty.meadow.cafe/u/username/slug
// - //kitty.meadow.cafe/u/username/slug
func parseInternalURL(url string) (username, slug string) {
	url = strings.TrimSpace(url)

	// Handle absolute URLs
	if strings.HasPrefix(url, constants.PUBLIC_URL) {
		url = strings.TrimPrefix(url, constants.PUBLIC_URL)
	} else if strings.HasPrefix(url, strings.Replace(constants.PUBLIC_URL, "https://", "http://", 1)) {
		url = strings.TrimPrefix(url, strings.Replace(constants.PUBLIC_URL, "https://", "http://", 1))
	} else if strings.HasPrefix(url, strings.TrimPrefix(constants.PUBLIC_URL, "https:")) {
		url = strings.TrimPrefix(url, strings.TrimPrefix(constants.PUBLIC_URL, "https:"))
	}

	// Now we should have a relative path like /u/username/slug
	if !strings.HasPrefix(url, "/u/") {
		return "", ""
	}

	// Remove /u/ prefix
	url = strings.TrimPrefix(url, "/u/")

	// Split by /
	parts := strings.Split(url, "/")
	if len(parts) < 2 {
		return "", ""
	}

	username = parts[0]
	slug = parts[1]

	// Remove any query params or anchors from slug
	if idx := strings.IndexAny(slug, "?#"); idx != -1 {
		slug = slug[:idx]
	}

	return username, slug
}

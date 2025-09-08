package site

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"kitty/constants"
	"kitty/database"
	"log"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	gmtext "git.sr.ht/~kota/goldmark-gemtext"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

const (
	geminiListenPort = ":19666"
	geminiCertFile   = "cert/gemini_cert.pem"
	geminiKeyFile    = "cert/gemini_key.pem"
)

func StartGeminiServer() {
	// Ensure cert files exist
	if _, err := os.Stat(geminiCertFile); err != nil {
		panic(missingCertsMessage("certificate", geminiCertFile, geminiKeyFile))
	}
	if _, err := os.Stat(geminiKeyFile); err != nil {
		panic(missingCertsMessage("key", geminiCertFile, geminiKeyFile))
	}

	certPair, err := tls.LoadX509KeyPair(geminiCertFile, geminiKeyFile)
	if err != nil {
		panic(fmt.Sprintf("Failed loading Gemini certificate/key: %v", err))
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{certPair},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", geminiListenPort, cfg)
	if err != nil {
		panic(fmt.Sprintf("Failed starting Gemini listener: %v", err))
	}

	log.Printf("Gemini listening on gemini://localhost%s", geminiListenPort)

	for {
		c, err := ln.Accept()
		if err != nil {
			// Accept errors are transient; log and continue.
			log.Printf("Gemini accept error: %v", err)
			continue
		}
		tc, ok := c.(*tls.Conn)
		if !ok {
			log.Printf("Gemini accept: received non-TLS connection type")
			_ = c.Close()
			continue
		}
		log.Printf("Gemini: new connection from %s", c.RemoteAddr().String())
		go handleGeminiConn(tc)
	}
}

func missingCertsMessage(kind, certPath, keyPath string) string {
	return fmt.Sprintf(
		"Missing Gemini TLS %s file. Expected:\n  %s\n  %s\nGenerate with:\n  openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj \"/CN=localhost\" -keyout %s -out %s\n",
		kind, certPath, keyPath, keyPath, certPath,
	)
}

// Gemini status/meta helpers
func gemStatusLine(code, meta string) string {
	return fmt.Sprintf("%s %s\r\n", code, meta)
}

func writeGemError(conn *tls.Conn, code, meta string) {
	_, _ = conn.Write([]byte(gemStatusLine(code, meta)))
}

func handleGeminiConn(conn *tls.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	// Read first line (URL request) up to CRLF or 2048 bytes
	reader := bufio.NewReader(conn)
	var b strings.Builder
	for {
		if b.Len() > 2048 {
			writeGemError(conn, "59", "Request too long")
			return
		}
		ch, err := reader.ReadByte()
		if err != nil {
			writeGemError(conn, "59", "Failed reading request")
			return
		}
		if ch == '\n' {
			break
		}
		if ch != '\r' {
			b.WriteByte(ch)
		}
	}

	reqLine := strings.TrimSpace(b.String())
	if reqLine == "" {
		writeGemError(conn, "59", "Empty request")
		return
	}

	u, err := url.Parse(reqLine)
	if err != nil {
		writeGemError(conn, "59", "Bad URL")
		return
	}

	path := u.Path
	if path == "" {
		path = "/"
	}

	// Routing
	switch {
	case path == "/":
		serveGeminiHome(conn)
	case strings.HasPrefix(path, "/u/"):
		serveGeminiUserScoped(conn, path)
	default:
		writeGemError(conn, "51", "Not Found")
	}
}

func serveGeminiHome(conn *tls.Conn) {
	// Global recent published non-page posts (not limited to show_on_homepage to match example)
	// Include blog title for pattern: username - BlogTitle - PostTitle (if blog title present)
	type recentPost struct {
		Title         string
		Slug          string
		PublishedDate time.Time
		Username      string
	}
	var posts []recentPost
	database.GetDB().Table("posts").
		Select("posts.slug, posts.title, posts.published_date, admin_users.username").
		Joins("JOIN admin_users ON admin_users.id = posts.admin_user_id").
		Where("posts.published = ? AND posts.is_page = ?", true, false).
		Order("posts.published_date desc").
		Limit(constants.HOMEPAGE_RECENT_POSTS_LIMIT).
		Scan(&posts)

	ascii := []string{
		"```",
		"            /\\_/\\",
		"       ____ ( ^.^)  Kitty",
		"      /\\___/  >🍃",
		"      \\/_/_",
		"```",
	}
	var out strings.Builder
	for _, l := range ascii {
		out.WriteString(l + "\n")
	}
	out.WriteString("\n...\n\n")
	out.WriteString("Welcome to Kitty! This is the Gemini mirror of the content hosted on the main site.\n")

	out.WriteString("To create your own blog, go to " + constants.PUBLIC_URL + "\n\n")
	out.WriteString("## Latest posts:\n\n")
	if len(posts) == 0 {
		out.WriteString("No posts yet.\n")
	} else {
		for _, p := range posts {
			out.WriteString(fmt.Sprintf("=> /u/%s/%s %s %s - %s\n",
				urlPathEscape(p.Username),
				urlPathEscape(p.Slug),
				p.PublishedDate.Format("2006-01-02"),
				p.Username,
				strings.TrimSpace(p.Title)))
		}
	}
	out.WriteString("\n")
	writeGemSuccess(conn, out.String()) // end home
}

func serveGeminiUserScoped(conn *tls.Conn, path string) {
	trimmed := strings.TrimPrefix(path, "/u/")
	if trimmed == "" {
		writeGemError(conn, "51", "Not Found")
		return
	}
	parts := strings.Split(trimmed, "/")
	usernameEsc := parts[0]
	if usernameEsc == "" {
		writeGemError(conn, "51", "Not Found")
		return
	}
	username, err := url.PathUnescape(usernameEsc)
	if err != nil {
		writeGemError(conn, "59", "Bad username")
		return
	}

	// Load user
	var user database.AdminUser
	if err := database.GetDB().Where("username = ?", username).First(&user).Error; err != nil {
		writeGemError(conn, "51", "User not found")
		return
	}

	// Determine sub-route
	if len(parts) == 1 || parts[1] == "" {
		serveGeminiUserRoot(conn, &user)
		return
	}

	// Archive
	if parts[1] == "archive" && len(parts) == 2 {
		serveGeminiArchive(conn, &user)
		return
	}

	// Tag page
	if parts[1] == "tag" && len(parts) == 3 {
		tagSeg, _ := url.PathUnescape(parts[2])
		serveGeminiTag(conn, &user, tagSeg)
		return
	}

	// Post slug (page or post)
	if len(parts) == 2 {
		slugSeg, _ := url.PathUnescape(parts[1])
		serveGeminiPost(conn, &user, slugSeg)
		return
	}

	writeGemError(conn, "51", "Not Found")
}

func serveGeminiUserRoot(conn *tls.Conn, user *database.AdminUser) {
	// If a homepage page is configured and valid, render it (same behavior as HTTP)
	if user.HomePagePostID != nil {
		var page database.Post
		if err := database.GetDB().Where("id = ? AND admin_user_id = ? AND published = ? AND is_page = ?", *user.HomePagePostID, user.ID, true, true).First(&page).Error; err == nil {
			renderGeminiPost(conn, user, &page)
			return
		}
	}

	// Fallback: archive view (mirrors HTTP fallback to archive)
	serveGeminiArchive(conn, user)
}

func serveGeminiArchive(conn *tls.Conn, user *database.AdminUser) {
	var posts []database.Post
	database.GetDB().Where("admin_user_id = ? AND published = ? AND is_page = ?", user.ID, true, false).
		Order("published_date DESC").
		Limit(constants.ARCHIVE_MAX_POSTS).
		Find(&posts)

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

	var out strings.Builder

	// Header
	if strings.TrimSpace(user.HeaderMarkdown) != "" {
		header := convertMarkdownToGemtext(user.HeaderMarkdown, user)
		header = strings.TrimSpace(header)
		if header != "" {
			out.WriteString(header + "\n\n")
		}
	}

	out.WriteString("# Archive\n\n")
	if len(posts) == 0 {
		out.WriteString("No posts yet.\n")
		writeGemSuccess(conn, out.String())
		return
	}

	for _, y := range years {
		out.WriteString(fmt.Sprintf("## %d\n\n", y))
		for _, p := range yearMap[y] {
			date := p.PublishedDate.Format("2006-01-02")
			// Standardized single-line format: link, date, title
			out.WriteString(fmt.Sprintf("=> /u/%s/%s %s %s\n",
				url.PathEscape(user.Username),
				url.PathEscape(p.Slug),
				date,
				escapeGemtextLine(p.Title),
			))
		}
		out.WriteString("\n")
	}

	// Navigation links (author home + archive)
	out.WriteString("## Navigation\n")
	out.WriteString(fmt.Sprintf("=> /u/%s %s home\n", user.Username, url.PathEscape(user.Username)))

	writeGemSuccess(conn, out.String())
}

func serveGeminiTag(conn *tls.Conn, user *database.AdminUser, tag string) {
	var posts []database.Post
	database.GetDB().Where("admin_user_id = ? AND published = ?", user.ID, true).
		Order("published_date DESC").
		Limit(constants.MAX_POSTS_TO_SHOW).
		Find(&posts)

	lowerTag := strings.ToLower(tag)
	var matched []database.Post
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

	var out strings.Builder
	if strings.TrimSpace(user.HeaderMarkdown) != "" {
		header := convertMarkdownToGemtext(user.HeaderMarkdown, user)
		header = strings.TrimSpace(header)
		if header != "" {
			out.WriteString(header + "\n\n")
		}
	}
	out.WriteString("# Tag: " + escapeGemtextLine(tag) + "\n\n")
	if len(matched) == 0 {
		out.WriteString("No posts found for this tag.\n")
		writeGemSuccess(conn, out.String())
		return
	}
	for _, p := range matched {
		date := p.PublishedDate.Format("2006-01-02")
		// Standardized single-line format: link, date, title
		out.WriteString(fmt.Sprintf("=> /u/%s/%s %s %s\n",
			url.PathEscape(user.Username),
			url.PathEscape(p.Slug),
			date,
			escapeGemtextLine(p.Title),
		))
	}
	out.WriteString("\n")

	out.WriteString("## Navigation\n")
	out.WriteString(fmt.Sprintf("=> /u/%s %s home\n", user.Username, url.PathEscape(user.Username)))
	out.WriteString(fmt.Sprintf("=> /u/%s/archive Archive\n\n", url.PathEscape(user.Username)))

	writeGemSuccess(conn, out.String())
}

func serveGeminiPost(conn *tls.Conn, user *database.AdminUser, slug string) {
	var post database.Post
	if err := database.GetDB().Where("slug = ? AND admin_user_id = ? AND published = ?", slug, user.ID, true).First(&post).Error; err != nil {
		writeGemError(conn, "51", "Post not found")
		return
	}
	renderGeminiPost(conn, user, &post)
}

func renderGeminiPost(conn *tls.Conn, user *database.AdminUser, post *database.Post) {
	var out strings.Builder
	// Header
	if strings.TrimSpace(user.HeaderMarkdown) != "" {
		header := convertMarkdownToGemtext(user.HeaderMarkdown, user)
		header = strings.TrimSpace(header)
		if header != "" {
			out.WriteString(header + "\n\n")
		}
	}
	out.WriteString("# " + escapeGemtextLine(post.Title) + "\n\n")
	if !post.IsPage {
		out.WriteString(fmt.Sprintf("Published: %s\n\n", post.PublishedDate.Format("2006-01-02")))
	}
	bodyGem := convertMarkdownToGemtext(post.Body, user)
	bodyGem = strings.TrimSpace(bodyGem)
	if bodyGem != "" {
		out.WriteString(bodyGem + "\n\n")
	}
	// Tags
	var tags []string
	_ = json.Unmarshal(post.Tags, &tags)
	cleanTags := make([]string, 0, len(tags))
	for _, t := range tags {
		tt := strings.TrimSpace(t)
		if tt != "" {
			cleanTags = append(cleanTags, tt)
		}
	}
	if len(cleanTags) > 0 {
		out.WriteString("## Tags\n")
		for _, t := range cleanTags {
			out.WriteString(fmt.Sprintf("=> /u/%s/tag/%s %s\n", url.PathEscape(user.Username), url.PathEscape(t), escapeGemtextLine(t)))
		}
		out.WriteString("\n")
	}
	// Navigation links (author home + archive)
	out.WriteString("## Navigation\n")
	out.WriteString(fmt.Sprintf("=> /u/%s %s home\n", user.Username, url.PathEscape(user.Username)))
	out.WriteString(fmt.Sprintf("=> /u/%s/archive Archive\n\n", url.PathEscape(user.Username)))
	writeGemSuccess(conn, out.String())
}

func writeGemSuccess(conn *tls.Conn, body string) {
	_, _ = conn.Write([]byte(gemStatusLine("20", "text/gemini")))
	_, _ = conn.Write([]byte(body))
	if !strings.HasSuffix(body, "\n") {
		_, _ = conn.Write([]byte("\n"))
	}
}

var gemtextMarkdown = goldmark.New(
	goldmark.WithExtensions(
		extension.Linkify,
		extension.Strikethrough,
	),
	goldmark.WithRenderer(gmtext.New()),
)

// convertMarkdownToGemtext renders Markdown to Gemtext using goldmark + goldmark-gemtext.
// Shortcodes are expanded first. Falls back to original markdown on error.
func convertMarkdownToGemtext(md string, user *database.AdminUser) string {
	// Gemini-specific shortcode expansion (produces Gemtext-friendly lines)
	expanded := applyShortcodesToContent(md, user)

	// Replace horizontal rules '---' with a visible separator (Gemtext has no <hr>)
	reHR := regexp.MustCompile(`(?m)^\s*---\s*$`)
	expanded = reHR.ReplaceAllString(expanded, "\n...\n")

	// Convert dated markdown list items with inline links to Gemini link lines.
	// Example source:
	// - `2025-09-08` — [Rescuing a Blackbird](/u/qwfqwf/rescuing-a-blackbird)
	// Result:
	// [2025-09-08 — Rescuing a Blackbird](/u/qwfqwf/rescuing-a-blackbird)
	// Generic rule: if a list item ( - / * / + ) contains exactly ONE Markdown link, convert the
	// entire list item (minus the list marker) into a single link line whose label is the full
	// textual content of that list item (with the original link's anchor text in place, URL removed).
	// This gracefully covers dated entries, pages with descriptions, etc., without bespoke regexes.
	var (
		reListBulletRemainder = regexp.MustCompile(`^[\-\*\+]\s+(.*)$`)
		reMarkdownLink        = regexp.MustCompile(`\[([^\]]+)\]\((/[^)]+)\)`) // capture text + relative URL
		reBacktickDate        = regexp.MustCompile("`([0-9]{4}-[0-9]{2}-[0-9]{2})`")
	)
	var convertedLines []string
	for _, line := range strings.Split(expanded, "\n") {
		trim := strings.TrimSpace(line)
		if m := reListBulletRemainder.FindStringSubmatch(trim); len(m) == 2 {
			bulletBody := m[1]
			links := reMarkdownLink.FindAllStringSubmatch(bulletBody, -1)
			if len(links) == 1 {
				linkText := links[0][1]
				linkURL := links[0][2]
				// Replace the link markup with just its anchor text
				label := reMarkdownLink.ReplaceAllString(bulletBody, linkText)
				// Remove backticks from dates like `2025-09-08`
				label = reBacktickDate.ReplaceAllString(label, "$1")
				// Clean double dashes spacing (optional aesthetic)
				label = strings.TrimSpace(label)
				// Collapse internal excessive whitespace
				label = regexp.MustCompile(`\s+`).ReplaceAllString(label, " ")
				convertedLines = append(convertedLines, fmt.Sprintf("[%s](%s)", escapeGemtextLine(label), linkURL))
				continue
			}
		}
		convertedLines = append(convertedLines, line)
	}
	expanded = strings.Join(convertedLines, "\n")

	var buf bytes.Buffer
	if err := gemtextMarkdown.Convert([]byte(expanded), &buf); err != nil {
		return expanded
	}

	gemt := buf.String()

	// collapse multiple newlines to max 2
	reMultiNL := regexp.MustCompile(`\n{3,}`)
	gemt = reMultiNL.ReplaceAllString(gemt, "\n\n")

	return gemt
}

func escapeGemtextLine(s string) string {
	// Basic sanitization: tabs to spaces
	s = strings.ReplaceAll(s, "\t", "  ")
	return strings.TrimRightFunc(s, func(r rune) bool { return r == '\r' || r == '\n' })
}

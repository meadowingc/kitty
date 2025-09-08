package site

import (
	"encoding/json"
	"fmt"
	"kitty/constants"
	"kitty/database"
	"regexp"
	"sort"
	"strings"
)

// Regex for {posts}, {posts:N}, {posts:N:tag=foo}, {posts:tag=foo}, order of captures:
// 1: optional number
// 2: optional tag (without 'tag=')
var postsShortcodeRe = regexp.MustCompile(`\{posts(?::(?:(\d+)|tag=([A-Za-z0-9_\-]+))){0,2}(?::tag=([A-Za-z0-9_\-]+))?\}`)

// Regex for {archive}
var archiveShortcodeRe = regexp.MustCompile(`\{archive\}`)

// applyShortcodesToContent processes supported shortcodes for a given user's content BEFORE markdown parsing.
func applyShortcodesToContent(content string, user *database.AdminUser) string {
	if user == nil {
		return content
	}
	needsPosts := postsShortcodeRe.MatchString(content)
	needsArchive := archiveShortcodeRe.MatchString(content)

	if !needsPosts && !needsArchive {
		return content
	}

	// Preload published non-page posts once.
	var posts []database.Post
	if needsPosts || needsArchive {
		database.GetDB().
			Where("admin_user_id = ? AND published = ? AND is_page = ?", user.ID, true, false).
			Order("published_date DESC").
			Limit(constants.MAX_POSTS_TO_SHOW).
			Find(&posts)
	}

	// Handle {posts...} shortcodes
	content = postsShortcodeRe.ReplaceAllStringFunc(content, func(m string) string {
		// Extract captures by re-running FindStringSubmatch
		sm := postsShortcodeRe.FindStringSubmatch(m)
		limitStr1 := ""
		tag1 := ""
		tag2 := ""
		// sm indices: 0 full, 1 maybe number, 2 maybe tag (from first alt), 3 maybe tag (from second position)
		if len(sm) == 4 {
			limitStr1 = sm[1]
			tag1 = sm[2]
			tag2 = sm[3]
		}
		tagFilter := firstNonEmpty(tag1, tag2)
		limit := constants.SHORTCODE_DEFAULT_POST_LIMIT
		if limitStr1 != "" {
			if v, err := strconvAtoiSafe(limitStr1); err == nil {
				limit = v
			}
		}
		if limit <= 0 {
			limit = constants.SHORTCODE_DEFAULT_POST_LIMIT
		}
		if limit > constants.SHORTCODE_MAX_POST_LIMIT {
			limit = constants.SHORTCODE_MAX_POST_LIMIT
		}

		var filtered []database.Post
		lowerTag := strings.ToLower(tagFilter)
		for _, p := range posts {
			if tagFilter != "" {
				var tagList []string
				_ = json.Unmarshal(p.Tags, &tagList)
				match := false
				for _, t := range tagList {
					if strings.ToLower(strings.TrimSpace(t)) == lowerTag {
						match = true
						break
					}
				}
				if !match {
					continue
				}
			}
			filtered = append(filtered, p)
			if len(filtered) >= limit {
				break
			}
		}

		if len(filtered) == 0 {
			if tagFilter != "" {
				return fmt.Sprintf("_No posts found for tag '%s'._", tagFilter)
			}
			return "_No posts found._"
		}

		var b strings.Builder
		for _, p := range filtered {
			date := p.PublishedDate.Format("2006-01-02")
			b.WriteString(fmt.Sprintf("- `%s` — [%s](/u/%s/%s)\n",
				date,
				escapeMarkdownLinkText(p.Title),
				urlPathEscape(user.Username),
				urlPathEscape(p.Slug),
			))
		}
		return b.String()
	})

	// Handle {archive}
	if needsArchive {
		content = archiveShortcodeRe.ReplaceAllStringFunc(content, func(_ string) string {
			if len(posts) == 0 {
				return "_No posts yet._"
			}
			// Limit for archive
			max := constants.ARCHIVE_MAX_POSTS
			if max > len(posts) {
				max = len(posts)
			}
			selected := posts[:max]

			// Group by year
			type yearGroup struct {
				Year  int
				Posts []database.Post
			}
			yearMap := map[int][]database.Post{}
			for _, p := range selected {
				y := p.PublishedDate.Year()
				yearMap[y] = append(yearMap[y], p)
			}
			var years []int
			for y := range yearMap {
				years = append(years, y)
			}
			sort.Sort(sort.Reverse(sort.IntSlice(years)))

			var b strings.Builder
			for _, y := range years {
				b.WriteString(fmt.Sprintf("### %d\n\n", y))
				for _, p := range yearMap[y] {
					date := p.PublishedDate.Format("2006-01-02")
					b.WriteString(fmt.Sprintf("* `%s` — [%s](/u/%s/%s)\n",
						date,
						escapeMarkdownLinkText(p.Title),
						urlPathEscape(user.Username),
						urlPathEscape(p.Slug)))
				}
				b.WriteString("\n")
			}
			return b.String()
		})
	}

	return content
}

// Helper: safe Atoi
func strconvAtoiSafe(s string) (int, error) {
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Escape brackets in link text minimally (basic)
func escapeMarkdownLinkText(s string) string {
	s = strings.ReplaceAll(s, "[", "\\[")
	s = strings.ReplaceAll(s, "]", "\\]")
	return s
}

// URL Path escape (avoid importing net/url multiple times here)
func urlPathEscape(s string) string {
	// Allow simple runes; fallback to standard library in future if needed
	replacer := strings.NewReplacer(" ", "-", "%", "%25", "#", "%23", "?", "%3F")
	return replacer.Replace(s)
}

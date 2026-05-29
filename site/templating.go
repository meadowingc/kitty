package site

import (
	"encoding/json"
	stdhtml "html"
	"html/template"
	"io"
	"kitty/constants"
	"kitty/database"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/csrf"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/ast"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"gorm.io/datatypes"
)

var templatesCache sync.Map

func RenderTemplate(w http.ResponseWriter, r *http.Request, templateName string, data any) {
	type GlobalTemplateData struct {
		CurrentUser      *database.AdminUser
		ViewingUser      *database.AdminUser
		IsDebug          bool
		SiteName         string
		PublicURL        string
		DisplaySiteTitle string
		DisplayEmoji     string
		HeaderHTML       template.HTML
		CustomCSS        template.CSS
		RequestPath      string
		CSRFField        template.HTML
		CSRFToken        string
	}

	currentUser := getSignedInUserOrNil(r)
	viewingUser := getViewingUserFromContext(r)

	displayTitle := constants.APP_NAME
	if viewingUser != nil {
		if strings.TrimSpace(viewingUser.BlogTitle) != "" {
			displayTitle = strings.TrimSpace(viewingUser.BlogTitle)
		} else if strings.TrimSpace(viewingUser.Username) != "" {
			displayTitle = viewingUser.Username
		}
	}

	displayEmoji := "😺"
	if viewingUser != nil && strings.TrimSpace(viewingUser.Emoji) != "" {
		displayEmoji = strings.TrimSpace(viewingUser.Emoji)
	}

	var headerHTML template.HTML
	if viewingUser != nil && strings.TrimSpace(viewingUser.HeaderMarkdown) != "" {
		headerSrc := applyShortcodesToContent(viewingUser.HeaderMarkdown, viewingUser)
		extensions := parser.CommonExtensions | parser.AutoHeadingIDs | parser.Footnotes | parser.Autolink
		p := parser.NewWithExtensions(extensions)
		doc := p.Parse([]byte(headerSrc))
		htmlFlags := html.CommonFlags | html.HrefTargetBlank | html.FootnoteReturnLinks | html.SkipHTML
		opts := html.RendererOptions{
			Flags:          htmlFlags,
			RenderNodeHook: safeMarkdownRenderHook,
		}
		renderer := html.NewRenderer(opts)
		rendered := markdown.Render(doc, renderer)
		headerHTML = template.HTML(rendered)
	}

	var customCSS template.CSS
	if viewingUser != nil && strings.TrimSpace(viewingUser.CustomCSS) != "" {
		customCSS = template.CSS(viewingUser.CustomCSS)
	}

	templateData := struct {
		Global GlobalTemplateData
		Data   any
	}{
		Global: GlobalTemplateData{
			CurrentUser:      currentUser,
			ViewingUser:      viewingUser,
			IsDebug:          constants.DEBUG_MODE,
			SiteName:         constants.APP_NAME,
			PublicURL:        constants.PUBLIC_URL,
			DisplaySiteTitle: displayTitle,
			DisplayEmoji:     displayEmoji,
			HeaderHTML:       headerHTML,
			CustomCSS:        customCSS,
			RequestPath:      r.URL.Path,
			CSRFField:        csrf.TemplateField(r),
			CSRFToken:        csrf.Token(r),
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
			"jsonListToSlice": func(jsonList datatypes.JSON) []string {
				var tags []string
				_ = json.Unmarshal(jsonList, &tags)
				out := make([]string, 0, len(tags))
				for _, t := range tags {
					tt := strings.TrimSpace(t)
					if tt != "" {
						out = append(out, tt)
					}
				}
				return out
			},
			"parseMarkdown": func(markdownStr string) template.HTML {
				// Apply shortcodes (posts/archive) prior to markdown rendering using viewing user context
				processed := applyShortcodesToContent(markdownStr, viewingUser)
				extensions := parser.CommonExtensions | parser.AutoHeadingIDs | parser.Footnotes
				p := parser.NewWithExtensions(extensions)
				doc := p.Parse([]byte(processed))

				htmlFlags := html.CommonFlags | html.HrefTargetBlank | html.FootnoteReturnLinks | html.SkipHTML
				opts := html.RendererOptions{
					Flags:          htmlFlags,
					RenderNodeHook: safeMarkdownRenderHook,
				}
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
			"pathEscape": func(s string) string {
				return url.PathEscape(s)
			},
			"uintPtrEq": func(a uint, b *uint) bool { return b != nil && a == *b },
			"isHomePageView": func(requestPath, username string, isPage bool) bool {
				return isPage && requestPath == "/u/"+url.PathEscape(username)
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

// isSafeURL checks if a given URL scheme is safe (preventing javascript/data protocol execution)
func isSafeURL(urlStr string) bool {
	urlStr = strings.TrimSpace(urlStr)
	unescaped := stdhtml.UnescapeString(urlStr)
	lower := strings.ToLower(unescaped)

	// If no scheme is present, or if a path separator appears before the first colon,
	// it's a relative path (e.g. /u/username/post, or u/username), which is safe.
	colonIdx := strings.Index(lower, ":")
	slashIdx := strings.Index(lower, "/")
	if colonIdx == -1 || (slashIdx != -1 && slashIdx < colonIdx) {
		return true
	}

	// Only allow specific safe protocols
	scheme := lower[:colonIdx]
	return scheme == "http" || scheme == "https" || scheme == "mailto" || scheme == "tel" || scheme == "gemini"
}

// safeMarkdownRenderHook intercepts ast.Link and ast.Image rendering to strip unsafe URL protocols
func safeMarkdownRenderHook(w io.Writer, node ast.Node, entering bool) (ast.WalkStatus, bool) {
	if link, ok := node.(*ast.Link); ok {
		dest := string(link.Destination)
		if !isSafeURL(dest) {
			link.Destination = []byte("#")
		}
		return ast.GoToNext, false
	}
	if img, ok := node.(*ast.Image); ok {
		dest := string(img.Destination)
		if !isSafeURL(dest) {
			img.Destination = []byte("")
		}
		return ast.GoToNext, false
	}
	return ast.GoToNext, false
}

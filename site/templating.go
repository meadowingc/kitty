package site

import (
	"encoding/json"
	"html/template"
	"kitty/constants"
	"kitty/database"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"gorm.io/datatypes"
)

var templatesCache sync.Map

func RenderTemplate(w http.ResponseWriter, r *http.Request, templateName string, data any) {
	type GlobalTemplateData struct {
		CurrentUser *database.AdminUser
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

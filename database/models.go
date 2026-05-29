package database

import (
	"net/url"
	"strings"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Post struct {
	gorm.Model
	AdminUserID     uint `gorm:"uniqueIndex:idx_user_slug"`
	Title           string
	Body            string `gorm:"type:text"`
	Slug            string `gorm:"uniqueIndex:idx_user_slug"`
	PublishedDate   time.Time
	IsPage          bool
	MetaDescription string
	MetaImage       string
	Lang            string
	Tags            datatypes.JSON
	Published       bool
	ShowOnHomepage  bool
}

type Backlink struct {
	gorm.Model
	SourcePostID uint `gorm:"index:idx_source_target,unique"`
	TargetPostID uint `gorm:"index:idx_source_target,unique;index:idx_target"`
}

type AdminUser struct {
	gorm.Model
	Username       string         `gorm:"uniqueIndex"`
	PasswordHash   datatypes.JSON `gorm:"type:json"`
	SessionToken   string         `gorm:"index;unique"`
	Posts          []Post         `gorm:"foreignKey:AdminUserID"`
	HomePagePostID *uint
	HeaderMarkdown string `gorm:"type:text"`
	BlogTitle      string
	Emoji          string
	ShowBacklinks  bool   `gorm:"default:true"`
	CustomCSS      string `gorm:"type:text"`
	WebAuthnHandle []byte `gorm:"type:blob"`
	PasswordLoginDisabled bool `gorm:"default:false"`
	Passkeys       []Passkey `gorm:"foreignKey:AdminUserID"`
}

// Passkey stores a single WebAuthn credential belonging to an AdminUser.
// Data holds the full webauthn.Credential serialized as JSON; CredentialID is
// the base64url-encoded credential ID kept separately for fast lookups.
type Passkey struct {
	gorm.Model
	AdminUserID  uint           `gorm:"index"`
	Name         string
	CredentialID string         `gorm:"uniqueIndex"`
	Data         datatypes.JSON `gorm:"type:json"`
}

func (u *AdminUser) BeforeCreate(tx *gorm.DB) (err error) {
	if strings.TrimSpace(u.HeaderMarkdown) == "" && strings.TrimSpace(u.Username) != "" {
		esc := url.PathEscape(u.Username)
		u.HeaderMarkdown = "[Home](/u/" + esc + ") | [Archive](/u/" + esc + "/archive) | [RSS](/u/" + esc + "/feed.xml)\n\n---"
	}
	return nil
}

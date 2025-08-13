package database

import (
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
}

type AdminUser struct {
	gorm.Model
	Username     string         `gorm:"uniqueIndex"`
	PasswordHash datatypes.JSON `gorm:"type:json"`
	SessionToken string         `gorm:"index;unique"`
	Posts        []Post         `gorm:"foreignKey:AdminUserID"`
}

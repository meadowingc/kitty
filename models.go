package main

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Post struct {
	gorm.Model
	AdminUserID      uint `gorm:"index"`
	Title            string
	Body             string `gorm:"type:text"`
	Slug             string
	PublishedDate    time.Time
	IsPage           bool
	MetaDescription  string
	MetaImage        string
	Lang             string
	Tags             datatypes.JSON
	MakeDiscoverable bool
}

type AdminUser struct {
	gorm.Model
	Username     string         `gorm:"uniqueIndex"`
	PasswordHash datatypes.JSON `gorm:"type:json"`
	SessionToken string         `gorm:"index;unique"`
	Posts        []Post         `gorm:"foreignKey:AdminUserID"`
}

func getPostWithSlug(slug string) (*Post, error) {
	var post Post
	result := db.Where("slug = ?", slug).First(&post)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, result.Error
	}
	return &post, nil
}

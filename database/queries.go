package database

import "gorm.io/gorm"

func GetPostWithSlug(slug string) (*Post, error) {
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

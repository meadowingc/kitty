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

func DeleteUserAndPosts(userID uint) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Hard delete (bypass soft delete) all posts for the user
		if err := tx.Unscoped().Where("admin_user_id = ?", userID).Delete(&Post{}).Error; err != nil {
			return err
		}
		// Hard delete the user record itself
		if err := tx.Unscoped().Delete(&AdminUser{}, userID).Error; err != nil {
			return err
		}
		return nil
	})
}

func GetPostWithSlugForUser(userID uint, slug string) (*Post, error) {
	var post Post
	result := db.Where("slug = ? AND admin_user_id = ?", slug, userID).First(&post)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, result.Error
	}
	return &post, nil
}

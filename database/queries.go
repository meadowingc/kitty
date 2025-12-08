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

type PostWithUser struct {
	Post
	Username string
}

func GetBacklinksForPost(postID uint) ([]PostWithUser, error) {
	var results []PostWithUser
	result := db.Table("posts").
		Select("posts.*, admin_users.username").
		Joins("INNER JOIN backlinks ON backlinks.source_post_id = posts.id").
		Joins("INNER JOIN admin_users ON admin_users.id = posts.admin_user_id").
		Where("backlinks.target_post_id = ? AND posts.published = ?", postID, true).
		Order("posts.published_date DESC").
		Find(&results)
	if result.Error != nil {
		return nil, result.Error
	}
	return results, nil
}

func SaveBacklinksForPost(sourcePostID uint, targetPostIDs []uint) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Delete existing backlinks for this source post
		if err := tx.Where("source_post_id = ?", sourcePostID).Delete(&Backlink{}).Error; err != nil {
			return err
		}

		// Insert new backlinks
		for _, targetID := range targetPostIDs {
			backlink := Backlink{
				SourcePostID: sourcePostID,
				TargetPostID: targetID,
			}
			if err := tx.Create(&backlink).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func GetPostByUsernameAndSlug(username, slug string) (*Post, error) {
	var user AdminUser
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}

	var post Post
	result := db.Where("slug = ? AND admin_user_id = ?", slug, user.ID).First(&post)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, result.Error
	}
	return &post, nil
}

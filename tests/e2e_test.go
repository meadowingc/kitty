package tests

import (
	"strings"
	"testing"
	"time"
)

// TestBacklinksFeature tests the complete backlinks functionality
func TestBacklinksFeature(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	// Create two users
	user1 := createTestUser(t, "alice", "password123")
	user2 := createTestUser(t, "bob", "password456")

	// User 1 creates a post
	slug1 := user1.createPost(t, "My First Post", "This is my first post about Go programming.", true)
	time.Sleep(200 * time.Millisecond) // Wait for async backlink processing

	// User 2 creates a post that links to User 1's post
	linkText := "[Check out this post](/u/alice/" + slug1 + ")"
	slug2 := user2.createPost(t, "Interesting Article", "I found this interesting: "+linkText, true)
	time.Sleep(500 * time.Millisecond) // Wait for async backlink processing

	// Navigate to User 1's post and verify backlink appears
	publicPage := getPublicPage(t)
	publicPage.MustNavigate(testBaseURL + "/u/alice/" + slug1)
	publicPage.MustWaitLoad()

	// Check for backlinks section
	backlinksSection := publicPage.MustElement(".post-backlinks")
	if backlinksSection == nil {
		t.Fatal("Backlinks section not found")
	}

	// Verify the backlink title appears
	backlinkText := backlinksSection.MustText()
	if !strings.Contains(backlinkText, "Interesting Article") {
		t.Errorf("Expected backlink title 'Interesting Article', got: %s", backlinkText)
	}

	// Verify username appears in backlink
	if !strings.Contains(backlinkText, "bob") {
		t.Errorf("Expected username 'bob' in backlink, got: %s", backlinkText)
	}

	// Verify the backlink is clickable
	backlinkLink := backlinksSection.MustElement("a")
	href := backlinkLink.MustProperty("href").String()
	if !strings.Contains(href, "/u/bob/"+slug2) {
		t.Errorf("Expected backlink to point to /u/bob/%s, got: %s", slug2, href)
	}
}

// TestBacklinksToggle tests the settings toggle for showing/hiding backlinks
func TestBacklinksToggle(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	// Create two users
	user1 := createTestUser(t, "charlie", "password123")
	user2 := createTestUser(t, "diana", "password456")

	// User 1 creates a post
	slug1 := user1.createPost(t, "Charlie's Post", "Hello world!", true)
	time.Sleep(200 * time.Millisecond)

	// User 2 creates a post linking to User 1's post
	linkText := "[Charlie's post](/u/charlie/" + slug1 + ")"
	user2.createPost(t, "Diana's Post", "Linking to: "+linkText, true)
	time.Sleep(500 * time.Millisecond)

	// Verify backlinks are shown by default
	publicPage := getPublicPage(t)
	publicPage.MustNavigate(testBaseURL + "/u/charlie/" + slug1)
	publicPage.MustWaitLoad()

	// Backlinks should be visible by default
	if !publicPage.MustHas(".post-backlinks") {
		t.Error("Backlinks should be visible by default")
	}

	// User 1 disables backlinks in settings
	user1.navigateToSettings(t)
	checkbox := user1.Page.MustElement("#showBacklinks")
	if checkbox.MustProperty("checked").Bool() {
		checkbox.MustClick()
	}
	user1.Page.MustElement("button[type=submit]").MustClick()
	user1.Page.MustWaitLoad()

	// Verify backlinks are now hidden
	publicPage.MustNavigate(testBaseURL + "/u/charlie/" + slug1)
	publicPage.MustWaitLoad()

	if publicPage.MustHas(".post-backlinks") {
		t.Error("Backlinks should be hidden after disabling in settings")
	}
}

// TestMultipleBacklinks tests multiple posts linking to the same post
func TestMultipleBacklinks(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	// Create three users
	user1 := createTestUser(t, "emma", "password123")
	user2 := createTestUser(t, "frank", "password456")
	user3 := createTestUser(t, "grace", "password789")

	// User 1 creates a post
	slug1 := user1.createPost(t, "Popular Post", "This will get many backlinks.", true)
	time.Sleep(200 * time.Millisecond)

	// User 2 and 3 both link to User 1's post
	linkText := "[Emma's post](/u/emma/" + slug1 + ")"
	user2.createPost(t, "Frank's Response", "Responding to: "+linkText, true)
	time.Sleep(300 * time.Millisecond)
	user3.createPost(t, "Grace's Thoughts", "Thoughts on: "+linkText, true)
	time.Sleep(500 * time.Millisecond)

	// Verify both backlinks appear
	publicPage := getPublicPage(t)
	publicPage.MustNavigate(testBaseURL + "/u/emma/" + slug1)
	publicPage.MustWaitLoad()

	backlinksSection := publicPage.MustElement(".post-backlinks")
	backlinkText := backlinksSection.MustText()

	// Check for both titles
	if !strings.Contains(backlinkText, "Frank's Response") {
		t.Error("Expected to find Frank's Response in backlinks")
	}
	if !strings.Contains(backlinkText, "Grace's Thoughts") {
		t.Error("Expected to find Grace's Thoughts in backlinks")
	}
}

// TestAuthenticationFlow tests user signup, signin, and logout
func TestAuthenticationFlow(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	// Test signup
	user := createTestUser(t, "testuser", "testpass123")
	dashboardTitle := user.Page.MustElement("h1").MustText()
	if !strings.Contains(dashboardTitle, "Dashboard") && !strings.Contains(dashboardTitle, "Posts") {
		t.Errorf("Expected dashboard after signup, got: %s", dashboardTitle)
	}

	// Test logout
	user.Page.MustElement("form[action='/logout'] button").MustClick()
	user.Page.MustWaitLoad()

	// Should redirect to signin page
	currentURL := user.Page.MustInfo().URL
	if !strings.Contains(currentURL, "/signin") {
		t.Errorf("Expected to be redirected to /signin after logout, got: %s", currentURL)
	}

	// Test signin
	signedInUser := signInUser(t, "testuser", "testpass123")
	dashboardTitle = signedInUser.Page.MustElement("h1").MustText()
	if !strings.Contains(dashboardTitle, "Dashboard") && !strings.Contains(dashboardTitle, "Posts") {
		t.Errorf("Expected dashboard after signin, got: %s", dashboardTitle)
	}
}

// TestPostManagement tests creating, editing, and deleting posts
func TestPostManagement(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	user := createTestUser(t, "editor", "password123")

	// Create a post
	slug := user.createPost(t, "Test Post", "This is a test post body.", true)

	// Verify slug was created
	if slug == "" {
		t.Fatal("Post creation failed - no slug returned")
	}

	// Edit the post
	titleField := user.Page.MustElement("#title")
	titleField.MustSelectAllText()
	titleField.MustInput("Updated Test Post")
	bodyField := user.Page.MustElement("#body")
	bodyField.MustSelectAllText()
	bodyField.MustInput("This is the updated body.")
	user.Page.MustElement("button[type=submit]").MustClick()
	user.Page.MustWaitLoad()

	// Verify changes were saved
	updatedTitle := user.Page.MustElement("#title").MustProperty("value").String()
	if updatedTitle != "Updated Test Post" {
		t.Errorf("Expected title 'Updated Test Post', got: %s", updatedTitle)
	}

	// Delete the post
	user.Page.MustElement("form[action*='/delete'] button").MustClick()
	user.Page.MustWaitLoad()

	// Should redirect to dashboard
	currentURL := user.Page.MustInfo().URL
	if !strings.Contains(currentURL, "/dashboard") {
		t.Errorf("Expected to be redirected to dashboard after delete, got: %s", currentURL)
	}
}

// TestPublishUnpublishToggle tests the publish/unpublish functionality
func TestPublishUnpublishToggle(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	user := createTestUser(t, "publisher", "password123")

	// Create an unpublished post
	user.Page.MustNavigate(testBaseURL + "/dashboard/post/new")
	user.Page.MustWaitLoad()

	user.Page.MustElement("#title").MustInput("Draft Post")
	user.Page.MustElement("#body").MustInput("This is a draft.")
	// Don't check the published checkbox
	user.Page.MustElement("button[type=submit]").MustClick()
	user.Page.MustWaitLoad()

	slug := user.Page.MustElement("#slug").MustProperty("value").String()

	// Try to access as public (should fail)
	publicPage := getPublicPage(t)
	publicPage.MustNavigate(testBaseURL + "/u/publisher/" + slug)
	publicPage.MustWaitLoad()

	// Should show 404 or "Post not found"
	pageText := publicPage.MustElement("body").MustText()
	if !strings.Contains(pageText, "not found") && !strings.Contains(pageText, "404") {
		t.Error("Unpublished post should not be accessible publicly")
	}

	// Publish the post
	user.Page.MustElement("#published").MustClick()
	user.Page.MustElement("button[type=submit]").MustClick()
	user.Page.MustWaitLoad()

	time.Sleep(100 * time.Millisecond)

	// Now it should be accessible
	publicPage.MustNavigate(testBaseURL + "/u/publisher/" + slug)
	publicPage.MustWaitLoad()

	pageTitle := publicPage.MustElement("h1").MustText()
	if pageTitle != "Draft Post" {
		t.Errorf("Expected to see published post, got title: %s", pageTitle)
	}
}

// TestSettingsUpdate tests updating user settings
func TestSettingsUpdate(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	user := createTestUser(t, "settings_user", "password123")

	// Navigate to settings
	user.navigateToSettings(t)

	// Update blog title
	blogTitleField := user.Page.MustElement("#blogTitle")
	blogTitleField.MustSelectAllText()
	blogTitleField.MustInput("My Awesome Blog")

	// Update header markdown
	headerField := user.Page.MustElement("#headerMarkdown")
	headerField.MustSelectAllText()
	headerField.MustInput("[Home](/u/settings_user) | [About](/u/settings_user/about)")

	// Save settings
	user.Page.MustElement("button[type=submit]").MustClick()
	user.Page.MustWaitLoad()

	// Verify settings were saved
	blogTitle := user.Page.MustElement("#blogTitle").MustProperty("value").String()
	if blogTitle != "My Awesome Blog" {
		t.Errorf("Expected blog title 'My Awesome Blog', got: %s", blogTitle)
	}
}

// TestTagFiltering tests the tag filtering functionality
func TestTagFiltering(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	user := createTestUser(t, "tagger", "password123")

	// Create posts with different tags
	user.Page.MustNavigate(testBaseURL + "/dashboard/post/new")
	user.Page.MustWaitLoad()
	user.Page.MustElement("#title").MustInput("Go Post")
	user.Page.MustElement("#body").MustInput("About Go programming")
	user.Page.MustElement("#tags").MustInput("go, programming")
	user.Page.MustElement("#published").MustClick()
	user.Page.MustElement("button[type=submit]").MustClick()
	user.Page.MustWaitLoad()

	user.Page.MustNavigate(testBaseURL + "/dashboard/post/new")
	user.Page.MustWaitLoad()
	user.Page.MustElement("#title").MustInput("Rust Post")
	user.Page.MustElement("#body").MustInput("About Rust programming")
	user.Page.MustElement("#tags").MustInput("rust, programming")
	user.Page.MustElement("#published").MustClick()
	user.Page.MustElement("button[type=submit]").MustClick()
	user.Page.MustWaitLoad()

	time.Sleep(200 * time.Millisecond)

	// View tag page for "go"
	publicPage := getPublicPage(t)
	publicPage.MustNavigate(testBaseURL + "/u/tagger/tag/go")
	publicPage.MustWaitLoad()

	pageText := publicPage.MustElement("body").MustText()
	if !strings.Contains(pageText, "Go Post") {
		t.Error("Expected to find 'Go Post' on go tag page")
	}
	if strings.Contains(pageText, "Rust Post") {
		t.Error("Should not find 'Rust Post' on go tag page")
	}
}

// TestRSSFeed tests that the RSS feed is accessible
func TestRSSFeed(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	user := createTestUser(t, "rssuser", "password123")

	// Create a published post
	user.createPost(t, "RSS Test Post", "This should appear in the feed.", true)
	time.Sleep(200 * time.Millisecond)

	// Access RSS feed
	publicPage := getPublicPage(t)
	publicPage.MustNavigate(testBaseURL + "/u/rssuser/feed.xml")
	publicPage.MustWaitLoad()

	// Check that it contains RSS content
	pageText := publicPage.MustElement("body").MustText()
	if !strings.Contains(pageText, "<?xml") || !strings.Contains(pageText, "<rss") {
		t.Error("RSS feed should contain valid XML")
	}
	if !strings.Contains(pageText, "RSS Test Post") {
		t.Error("RSS feed should contain the post title")
	}
}

// TestArchivePage tests the archive page functionality
func TestArchivePage(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	user := createTestUser(t, "archiver", "password123")

	// Create multiple posts
	user.createPost(t, "Post 1", "First post content", true)
	user.createPost(t, "Post 2", "Second post content", true)
	user.createPost(t, "Post 3", "Third post content", true)
	time.Sleep(300 * time.Millisecond)

	// View archive page
	publicPage := getPublicPage(t)
	publicPage.MustNavigate(testBaseURL + "/u/archiver/archive")
	publicPage.MustWaitLoad()

	pageText := publicPage.MustElement("body").MustText()

	// All posts should appear in archive
	if !strings.Contains(pageText, "Post 1") {
		t.Error("Archive should contain Post 1")
	}
	if !strings.Contains(pageText, "Post 2") {
		t.Error("Archive should contain Post 2")
	}
	if !strings.Contains(pageText, "Post 3") {
		t.Error("Archive should contain Post 3")
	}

	// Should be grouped by year
	currentYear := time.Now().Year()
	if !strings.Contains(pageText, string(rune(currentYear))) {
		t.Errorf("Archive should contain current year %d", currentYear)
	}
}

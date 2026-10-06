package main

import (
	"context"
	"io"
	"kitty/database"
	"kitty/site"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/gorm"
)

func testDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	t.Setenv("KITTY_DB_PATH", filepath.Join(t.TempDir(), "kitty.db"))
	t.Setenv("KITTY_REQUIRE_DATABASE", "false")
	database.CloseDB()
	db := database.GetDB()
	t.Cleanup(func() { site.WaitForBacklinks(); database.CloseDB() })
	return db
}

func testListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestHealthRequiresWorkingDatabase(t *testing.T) {
	db, err := testDatabase(t).DB()
	if err != nil {
		t.Fatal(err)
	}
	handler := healthHandler(db)
	for _, closed := range []bool{false, true} {
		if closed {
			db.Close()
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "/healthz", nil))
		if closed {
			if response.Code != 503 {
				t.Fatal(response.Code)
			}
		} else if response.Code != 200 || response.Header().Get("X-Kitty-Revision") != buildRevision {
			t.Fatal("missing health/revision")
		}
	}
}

func TestShutdownDrainsRequestsAndBacklinks(t *testing.T) {
	db := testDatabase(t)
	target := database.Post{Title: "target", Slug: "target"}
	user := database.AdminUser{Username: "fixture"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	target.AdminUserID = user.ID
	source := database.Post{AdminUserID: user.ID, Title: "source", Slug: "source"}
	for _, post := range []*database.Post{&target, &source} {
		if err := db.Create(post).Error; err != nil {
			t.Fatal(err)
		}
	}
	requestEntered, requestRelease := make(chan struct{}), make(chan struct{})
	workEntered, workRelease := make(chan struct{}), make(chan struct{})
	if err := db.Callback().Create().Before("gorm:create").Register("hold_backlink", func(tx *gorm.DB) {
		if tx.Statement.Table == "backlinks" {
			close(workEntered)
			<-workRelease
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer db.Callback().Create().Remove("hold_backlink")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestEntered)
		<-requestRelease
		site.UpdateBacklinksAsync(source.ID, "[target](/u/fixture/target)")
		w.Write([]byte("saved"))
	})
	httpListener, geminiListener := testListener(t), testListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, httpListener, geminiListener, handler) }()
	clientDone := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + httpListener.Addr().String())
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
		clientDone <- err
	}()
	<-requestEntered
	cancel()
	select {
	case err := <-done:
		t.Fatalf("shutdown abandoned request: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(requestRelease)
	<-workEntered
	select {
	case err := <-done:
		t.Fatalf("shutdown abandoned backlinks: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(workRelease)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not finish")
	}
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.Model(&database.Backlink{}).Where("source_post_id = ? AND target_post_id = ?", source.ID, target.ID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("accepted backlink was not persisted: %d %v", count, err)
	}
}

func TestGeminiStartupFailureReleasesHTTPListener(t *testing.T) {
	testDatabase(t)
	t.Setenv("CSRF_AUTH_KEY", "test-only-secret-with-at-least-32-bytes")
	reserved := testListener(t)
	addr := reserved.Addr().String()
	reserved.Close()
	t.Setenv("KITTY_HTTP_ADDR", addr)
	t.Setenv("KITTY_REQUIRE_TLS", "true")
	t.Setenv("KITTY_GEMINI_CERT", filepath.Join(t.TempDir(), "missing.pem"))
	if err := run(context.Background()); err == nil {
		t.Fatal("missing required Gemini TLS certificate accepted")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal("HTTP listener leaked after Gemini startup failure")
	}
	listener.Close()
}

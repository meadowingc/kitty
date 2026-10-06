package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"kitty/database"
	"kitty/site"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

var buildRevision = "development"

func healthHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var tables int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&tables); err != nil {
			log.Printf("Health database check: %v", err)
			http.Error(w, "Database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-Kitty-Revision", buildRevision)
		w.Write([]byte("ok\n"))
	})
}

func run(ctx context.Context) error {
	db, err := database.GetDB().DB()
	if err != nil {
		return err
	}
	defer database.CloseDB()
	router := http.NewServeMux()
	router.Handle("/healthz", healthHandler(db))
	router.Handle("/", initRouter())
	addr := os.Getenv("KITTY_HTTP_ADDR")
	if addr == "" {
		addr = ":6835"
	}
	httpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("HTTP listener: %w", err)
	}
	defer httpListener.Close()
	geminiListener, err := site.NewGeminiListener()
	if err != nil {
		return err
	}
	defer geminiListener.Close()
	return serve(ctx, httpListener, geminiListener, router)
}

func serve(ctx context.Context, httpListener, geminiListener net.Listener, handler http.Handler) error {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	httpDone := make(chan error, 1)
	geminiDone := make(chan error, 1)
	go func() { httpDone <- server.Serve(httpListener) }()
	go func() { geminiDone <- site.ServeGemini(ctx, geminiListener) }()
	log.Printf("HTTP listening on %s; Gemini listening on %s", httpListener.Addr(), geminiListener.Addr())

	var result error
	select {
	case <-ctx.Done():
	case err := <-httpDone:
		result = fmt.Errorf("HTTP server stopped: %w", err)
		httpDone = nil
	case err := <-geminiDone:
		if err != nil {
			result = err
		} else if ctx.Err() == nil {
			result = errors.New("Gemini server stopped unexpectedly")
		}
		geminiDone = nil
	}
	stop()
	log.Print("Draining HTTP, Gemini and accepted backlink work")
	// Do not close SQLite underneath an accepted request, even if shutdown takes longer than expected.
	if err := server.Shutdown(context.Background()); err != nil {
		result = errors.Join(result, err)
	}
	if httpDone != nil {
		if err := <-httpDone; !errors.Is(err, http.ErrServerClosed) {
			result = errors.Join(result, err)
		}
	}
	if geminiDone != nil {
		result = errors.Join(result, <-geminiDone)
	}
	site.WaitForBacklinks()
	return result
}

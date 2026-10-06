package database

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB

func initDatabase() {
	dbPath := "kitty.db"
	if envPath := os.Getenv("KITTY_DB_PATH"); envPath != "" {
		dbPath = envPath
	}
	requireExisting := false
	if value := os.Getenv("KITTY_REQUIRE_DATABASE"); value != "" {
		var err error
		requireExisting, err = strconv.ParseBool(value)
		if err != nil {
			log.Fatalf("Invalid KITTY_REQUIRE_DATABASE: %v", err)
		}
	}
	var err error
	db, err = openDatabase(dbPath, requireExisting)
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}
}

func openDatabase(path string, requireExisting bool) (*gorm.DB, error) {
	mode := "rwc"
	if requireExisting {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("required database: %w", err)
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return nil, fmt.Errorf("required database is not a nonempty regular file")
		}
		mode = "rw"
	}
	uri := &url.URL{Path: path}
	db, err := gorm.Open(sqlite.Open("file:"+uri.String()+"?cache=shared&mode="+mode+"&_journal_mode=WAL"), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&Post{}, &AdminUser{}, &Backlink{}, &Passkey{}); err != nil {
		if connection, closeErr := db.DB(); closeErr == nil {
			if closeErr := connection.Close(); closeErr != nil {
				log.Printf("Closing database after migration failure: %v", closeErr)
			}
		}
		return nil, fmt.Errorf("migrating database: %w", err)
	}
	return db, nil
}

func GetDB() *gorm.DB {
	if db == nil {
		initDatabase()
	}
	return db
}

func CloseDB() {
	if db == nil {
		return
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Printf("Error on closing database connection: %v", err)
	} else {
		if err := sqlDB.Close(); err != nil {
			log.Printf("Error on closing database connection: %v", err)
		}
	}
	db = nil // Reset so GetDB() will reinitialize (used in tests)
}

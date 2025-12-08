package database

import (
	"log"
	"os"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB

func initDatabase() {
	dbPath := "kitty.db"
	if envPath := os.Getenv("KITTY_DB_PATH"); envPath != "" {
		dbPath = envPath
	}
	var err error
	db, err = gorm.Open(sqlite.Open("file:"+dbPath+"?cache=shared&mode=rwc&_journal_mode=WAL"), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// Migrate the schema
	err = db.AutoMigrate(&Post{}, &AdminUser{}, &Backlink{})
	if err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}
}

func GetDB() *gorm.DB {
	if db == nil {
		initDatabase()
	}
	return db
}

func CloseDB() {
	sqlDB, err := db.DB()
	if err != nil {
		log.Printf("Error on closing database connection: %v", err)
	} else {
		if err := sqlDB.Close(); err != nil {
			log.Printf("Error on closing database connection: %v", err)
		}
	}
}

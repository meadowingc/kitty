package database

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRequiredDatabaseDoesNotCreateState(t *testing.T) {
	for _, name := range []string{"absent.db", "absent/kitty.db", "absent.db?mode=rwc"} {
		path := filepath.Join(t.TempDir(), name)
		if db, err := openDatabase(path, true); err == nil {
			connection, _ := db.DB()
			connection.Close()
			t.Fatalf("required missing database opened: %s", name)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("missing database was created: %v", err)
		}
	}
	path := filepath.Join(t.TempDir(), "empty.db")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openDatabase(path, true); err == nil {
		t.Fatal("required empty database accepted")
	}
}

func TestExistingDatabaseAndLiteralPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kitty?mode=ro.db")
	db, err := openDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	user := AdminUser{Username: "preserved"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	connection, _ := db.DB()
	connection.Close()
	db, err = openDatabase(path, true)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ = db.DB()
	defer connection.Close()
	var found AdminUser
	if err := db.First(&found, user.ID).Error; err != nil || found.Username != user.Username {
		t.Fatalf("existing row changed: %v", err)
	}
}

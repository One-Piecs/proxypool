package database

import (
	"os"
	"path/filepath"

	"github.com/One-Piecs/proxypool/log"

	"github.com/One-Piecs/proxypool/config"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func connect() (err error) {
	// Default SQLite file path
	dbPath := "data/proxypool.db"

	// Check config override
	if url := config.Config().DatabaseUrl; url != "" {
		dbPath = url
	}
	// Check env override
	if url := os.Getenv("DATABASE_URL"); url != "" {
		dbPath = url
	}

	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Warnln("database: failed to create directory %s: %v", dir, err)
	}

	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err == nil {
		log.Infoln("database: successfully connected to sqlite: %s", dbPath)
	} else {
		DB = nil
		log.Warnln("database connection info: %s \n\t\tUse cache to store proxies", err.Error())
	}
	return
}

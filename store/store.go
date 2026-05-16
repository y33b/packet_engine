package storage

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"nexus/model"
)

type Storage struct {
	db *sql.DB
}

func NewStorage() *Storage {
	db, _ := sql.Open("sqlite3", "./ids.db")

	db.Exec(`
	CREATE TABLE IF NOT EXISTS alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT,
		type INTEGER,
		risk REAL,
		message TEXT,
		timestamp INTEGER
	);
	`)

	return &Storage{db: db}
}
func (s *Storage) SaveAlert(a model.Alert) {
	_, _ = s.db.Exec(`
	INSERT INTO alerts (ip, type, risk, message, timestamp)
	VALUES (?, ?, ?, ?, ?)
	`, a.IP, a.Type, a.Risk, a.Message, a.Timestamp)
}

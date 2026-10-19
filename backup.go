package guard

import (
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
)

func checkedSource(path string) (*sql.DB, error) {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", "file:"+url.PathEscape(absolute)+"?mode=ro")
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	if _, e = db.Exec("PRAGMA busy_timeout=10000"); e != nil {
		db.Close()
		return nil, e
	}
	var integrity string
	if e = db.QueryRow("PRAGMA integrity_check").Scan(&integrity); e != nil || integrity != "ok" {
		db.Close()
		return nil, errors.New("database integrity check failed")
	}
	return db, nil
}

// VACUUM INTO creates a transactionally consistent snapshot, including WAL state.
func BackupDatabase(source, destination string) error {
	db, e := checkedSource(source)
	if e != nil {
		return e
	}
	defer db.Close()
	// SQLite accepts an existing empty destination. Create it exclusively with
	// private permissions before SQLite writes any data, rather than chmod later.
	file, e := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(destination)
		}
	}()
	if _, e = db.Exec("VACUUM INTO ?", destination); e != nil {
		return e
	}
	if e = os.Chmod(destination, 0600); e != nil {
		return e
	}
	verified, e := checkedSource(destination)
	if e == nil {
		e = verified.Close()
	}
	complete = e == nil
	return e
}

// RestoreDatabase is only for an offline backend and a writable data directory.
func RestoreDatabase(destination, source string) error {
	staged := destination + ".restore-" + uid()
	defer os.Remove(staged)
	if e := BackupDatabase(source, staged); e != nil {
		return e
	}
	if os.Geteuid() == 0 {
		if e := os.Chown(staged, 10001, 10001); e != nil {
			return e
		}
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if e := os.Remove(destination + suffix); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	return os.Rename(staged, destination)
}

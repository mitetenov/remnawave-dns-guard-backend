package guard

import (
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPythonFernetAndUnicodeCredentialGolden(t *testing.T) {
	// Created by Python cryptography.Fernet using SHA256(APP_SECRET).
	const legacy = "gAAAAABq1eUDYpNeKrprfWZV4kC6SHkEpnY1IDTv1CO1lMUiwDcYusXEaSfr-JPMKbQBIbzjXN6TC4e-hqg5tL20NyNit44K9A=="
	cipher := newFernet(strings.Repeat("S", 32))
	plain, err := cipher.decrypt(legacy)
	if err != nil || string(plain) != "legacy-token" {
		t.Fatal(string(plain), err)
	}
	cfg := testConfig(":memory:")
	cfg.Username, cfg.Password = "админ😀", "секрет"
	if got := authRevision(cfg); got != "219a0c969efb4e258dce76c4c08c0de3be38e6ffb8ae4e8e8b197efde1c19997" {
		t.Fatal("Python JSON/HMAC compatibility changed", got)
	}
	for _, value := range []string{"", "invalid", legacy[:30], base64.URLEncoding.EncodeToString(make([]byte, 73))} {
		if _, err := cipher.decrypt(value); err == nil {
			t.Fatal("invalid Fernet token accepted")
		}
	}
	token, _ := base64.URLEncoding.DecodeString(legacy)
	token[28] ^= 1
	if _, err := cipher.decrypt(base64.URLEncoding.EncodeToString(token)); err == nil {
		t.Fatal("tampered Fernet token accepted")
	}
	if _, err := newFernet(strings.Repeat("X", 32)).decrypt(legacy); err == nil {
		t.Fatal("wrong APP_SECRET accepted")
	}
	for _, value := range []string{"", "Русский 😀", strings.Repeat("p", 32)} {
		plain, err := cipher.decrypt(cipher.encrypt([]byte(value)))
		if err != nil || string(plain) != value {
			t.Fatal("roundtrip failed", err)
		}
	}
}

func TestCredentialRotationPreservesOrdinaryRestartSessions(t *testing.T) {
	for _, change := range []string{"none", "username", "password"} {
		t.Run(change, func(t *testing.T) {
			e := newTestEnv(t)
			cookies := e.client.Jar.Cookies(mustURL(e.server.URL + "/api/auth/me"))
			session := e.one("SELECT * FROM sessions")
			if session == nil || len(cookies) == 0 {
				t.Fatal("missing session")
			}
			e.server.Close()
			_ = e.app.Close()
			if change == "username" {
				e.cfg.Username = "new-admin"
			} else if change == "password" {
				e.cfg.Password = "new-password"
			}
			e.open(false)
			for _, cookie := range cookies {
				cookie.Path = "/api"
			}
			e.client.Jar.SetCookies(mustURL(e.server.URL+"/api"), cookies)
			expected := 401
			if change == "none" {
				expected = 200
			}
			e.do("GET", "/api/auth/me", nil, expected)
		})
	}
}

func TestConsistentWALBackupRestoreAndRejectCorruption(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "источник.db")
	s, err := openStore(testConfig(source))
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	s.set("cloudflare_api_token", "persisted-test-token")
	backup := filepath.Join(dir, "backup.db")
	if err = BackupDatabase(source, backup); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(backup)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("backup permissions", err)
	}
	if err = BackupDatabase(source, backup); err == nil {
		t.Fatal("existing backup overwritten")
	}
	destination := filepath.Join(dir, "restored.db")
	if err = RestoreDatabase(destination, backup); err != nil {
		t.Fatal(err)
	}
	restored, err := openStore(testConfig(destination))
	if err != nil {
		t.Fatal(err)
	}
	if restored.get("cloudflare_api_token") != "persisted-test-token" {
		t.Fatal("WAL data not preserved")
	}
	_ = restored.db.Close()
	corrupt := filepath.Join(dir, "corrupt.db")
	if err = os.WriteFile(corrupt, []byte("not SQLite"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = RestoreDatabase(destination, corrupt); err == nil {
		t.Fatal("corrupt backup accepted")
	}
	db, err := sql.Open("sqlite", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var integrity string
	if err = db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatal("failed restore damaged destination", err)
	}
}

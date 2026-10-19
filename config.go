package guard

import (
	"errors"
	"os"
	"strings"
)

type Config struct {
	Username, Password, AppSecret, AgentToken, DatabasePath, PublicOrigin string
	CloudflareAPIToken, RemnawaveURL, RemnawaveAPIToken                   string
	CookieSecure                                                          bool
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
func configFromEnv() Config {
	return Config{Username: os.Getenv("ADMIN_USERNAME"), Password: os.Getenv("ADMIN_PASSWORD"), AppSecret: os.Getenv("APP_SECRET"), AgentToken: os.Getenv("AGENT_TOKEN"), DatabasePath: env("DATABASE_PATH", "/data/guard.db"), CookieSecure: strings.EqualFold(env("COOKIE_SECURE", "true"), "true"), PublicOrigin: strings.TrimRight(env("PUBLIC_ORIGIN", "https://guard.example.com"), "/"), CloudflareAPIToken: os.Getenv("CLOUDFLARE_API_TOKEN"), RemnawaveURL: os.Getenv("REMNAWAVE_URL"), RemnawaveAPIToken: os.Getenv("REMNAWAVE_API_TOKEN")}
}
func (c Config) validate() error {
	if c.Username == "" || c.Password == "" || len([]rune(c.AppSecret)) < 32 || len([]rune(c.AgentToken)) < 32 {
		return errors.New("set ADMIN_USERNAME, ADMIN_PASSWORD, APP_SECRET and AGENT_TOKEN; secrets must contain at least 32 characters")
	}
	if !strings.HasPrefix(c.PublicOrigin, "https://") && !strings.HasPrefix(c.PublicOrigin, "http://") {
		return errors.New("PUBLIC_ORIGIN must be an HTTP(S) origin")
	}
	return nil
}

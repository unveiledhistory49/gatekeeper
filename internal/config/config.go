// Package config loads 12-factor settings from GATEKEEPER_ env vars.
package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	DatabaseURL  string
	Addr         string
	Pepper       string
	SessionHours int

	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func Load() Config {
	hours, err := strconv.Atoi(getenv("GATEKEEPER_SESSION_HOURS", "12"))
	if err != nil || hours <= 0 {
		hours = 12
	}
	c := Config{
		DatabaseURL:      getenv("GATEKEEPER_DATABASE_URL", "sqlite://./gatekeeper.db"),
		Addr:             getenv("GATEKEEPER_ADDR", ":8080"),
		Pepper:           getenv("GATEKEEPER_PEPPER", "dev-pepper-change-me"),
		SessionHours:     hours,
		OIDCIssuer:       os.Getenv("GATEKEEPER_OIDC_ISSUER"),
		OIDCClientID:     os.Getenv("GATEKEEPER_OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("GATEKEEPER_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:  os.Getenv("GATEKEEPER_OIDC_REDIRECT_URL"),
	}
	if c.Pepper == "dev-pepper-change-me" {
		log.Println("WARNING: running with default API-key pepper; set GATEKEEPER_PEPPER in production")
	}
	return c
}

func (c Config) OIDCEnabled() bool {
	return c.OIDCIssuer != "" && c.OIDCClientID != "" && c.OIDCClientSecret != "" && c.OIDCRedirectURL != ""
}

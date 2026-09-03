// Package db opens the database (SQLite by default, Postgres via URL),
// applies embedded migrations, and rewrites ? placeholders for pgx.
package db

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "pgx"
)

// Open selects a driver from the URL scheme and returns a ready pool.
// Supported: sqlite://PATH, sqlite://:memory:, postgres://..., postgresql://...
func Open(url string) (*sql.DB, string, error) {
	switch {
	case strings.HasPrefix(url, "sqlite://"):
		path := strings.TrimPrefix(url, "sqlite://")
		dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
		if path == ":memory:" || path == "" {
			dsn = "file:gatekeeper_mem?mode=memory&cache=shared&_pragma=foreign_keys(1)"
		}
		pool, err := sql.Open(DriverSQLite, dsn)
		if err != nil {
			return nil, "", err
		}
		if path == ":memory:" || path == "" {
			// Shared-cache memory DBs must stay on one connection.
			pool.SetMaxOpenConns(1)
		}
		if err := pool.Ping(); err != nil {
			return nil, "", err
		}
		return pool, DriverSQLite, nil
	case strings.HasPrefix(url, "postgres://") || strings.HasPrefix(url, "postgresql://"):
		pool, err := sql.Open(DriverPostgres, url)
		if err != nil {
			return nil, "", err
		}
		if err := pool.Ping(); err != nil {
			return nil, "", err
		}
		return pool, DriverPostgres, nil
	default:
		return nil, "", fmt.Errorf("unsupported database URL scheme (want sqlite:// or postgres://)")
	}
}

// Rebind rewrites ? placeholders to $n for Postgres. SQLite uses ? natively.
func Rebind(driver, query string) string {
	if driver != DriverPostgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Migrate applies pending embedded migrations in filename order, once each.
func Migrate(pool *sql.DB) error {
	if _, err := pool.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("schema_version: %w", err)
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for i, name := range names {
		version := i + 1
		var have int
		if err := pool.QueryRow(`SELECT COUNT(*) FROM schema_version WHERE version = ?`, version).Scan(&have); err != nil {
			return fmt.Errorf("version check: %w", err)
		}
		if have > 0 {
			continue
		}
		raw, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := pool.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(raw)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version (version, applied_at) VALUES (?, ?)`, version, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Package testutil provides real-Postgres fixtures for integration tests.
// Tests need FORTIK_TEST_PG_URL (a superuser DSN, e.g.
// postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable); without it
// they are skipped with an explicit message (never silently passed).
package testutil

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/store"
)

const EnvPG = "FORTIK_TEST_PG_URL"

// AdminURL returns the superuser DSN or skips the test.
func AdminURL(t testing.TB) string {
	t.Helper()
	u := os.Getenv(EnvPG)
	if u == "" {
		t.Skipf("integration test skipped: set %s to a superuser Postgres DSN", EnvPG)
	}
	return u
}

// TempDB creates an empty uniquely-named database and drops it on cleanup.
// It returns the DSN of the new database.
func TempDB(t testing.TB, prefix string) string {
	t.Helper()
	admin := AdminURL(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer conn.Close(ctx)
	name := fmt.Sprintf("%s_%d_%d", prefix, time.Now().UnixNano(), os.Getpid())
	name = strings.ToLower(strings.NewReplacer("-", "_", "/", "_").Replace(name))
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), admin)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parse admin url: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// FortikDB creates a temp database, applies migrations and returns a pool.
func FortikDB(t testing.TB) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := TempDB(t, "fortik_test")
	ctx := context.Background()
	pool, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := store.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool, dsn
}

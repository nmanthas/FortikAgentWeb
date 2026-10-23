// Package secrets abstracts where powerful credentials live. Providers:
// encfile (AES-256-GCM files, the dev/pilot default), vault (KV v2 over HTTP;
// OpenBao compatible), and the read-only Phase 1 file and env providers.
// Secrets are never written to Postgres or logs; errors name secrets but
// never contain their values.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var ErrNotFound = errors.New("secret not found")

type Provider interface {
	Get(ctx context.Context, name string) ([]byte, error)
}

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)

// File reads <dir>/<name> (names may contain '/' for subdirectories; see
// ValidName). Intended for local development and pilots that mount secrets
// as files (e.g. Kubernetes secrets, Vault agent templates). Read-only.
type File struct{ Dir string }

func (f File) Get(_ context.Context, name string) ([]byte, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(f.Dir, filepath.FromSlash(name)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("read secret %s: %w", name, err)
	}
	return []byte(strings.TrimRight(string(b), "\r\n")), nil
}

// Env reads FORTIK_SECRET_<NAME> (upper-cased, '.'/'-' -> '_').
type Env struct{}

func (Env) Get(_ context.Context, name string) ([]byte, error) {
	if !namePattern.MatchString(name) {
		return nil, fmt.Errorf("invalid secret name %q", name)
	}
	key := "FORTIK_SECRET_" + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(name))
	v, ok := os.LookupEnv(key)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return []byte(v), nil
}

// New builds a Phase 1 read-only provider (file or env). Phase 2 callers use
// Open, which also builds the writable encfile and vault stores.
func New(provider, dir string) (Provider, error) {
	switch provider {
	case "file":
		return File{Dir: dir}, nil
	case "env":
		return Env{}, nil
	default:
		return nil, fmt.Errorf("unknown secret provider %q", provider)
	}
}

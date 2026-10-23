package secrets

import (
	"context"
	"errors"
)

// ErrReadOnly is returned by Put/Delete on read-only providers (file, env).
var ErrReadOnly = errors.New("secret provider is read-only")

// Store is a writable secret provider (encfile, vault). The console's
// Integrations screen writes credentials only through a Store; values are
// never persisted in Postgres or returned by any API.
type Store interface {
	Provider
	// Put creates or replaces a secret atomically.
	Put(ctx context.Context, name string, value []byte) error
	// Delete removes a secret; deleting a missing secret is not an error.
	Delete(ctx context.Context, name string) error
}

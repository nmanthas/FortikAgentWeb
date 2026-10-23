package secrets

import (
	"context"
	"fmt"

	"fortik/internal/config"
)

// Open builds the configured provider:
//
//	encfile  *EncFile (also a Store)
//	vault    *Vault   (also a Store)
//	file     File     (read-only)
//	env      Env      (read-only)
//
// Use AsStore to obtain a Store for any provider (read-only ones refuse
// writes with ErrReadOnly).
func Open(cfg config.SecretsConfig) (Provider, error) {
	switch cfg.Provider {
	case "encfile":
		return OpenEncFile(cfg)
	case "vault":
		return OpenVault(cfg)
	case "file":
		if cfg.Dir == "" {
			return nil, fmt.Errorf("secrets: dir is required for the file provider")
		}
		return File{Dir: cfg.Dir}, nil
	case "env":
		return Env{}, nil
	default:
		return nil, fmt.Errorf("unknown secret provider %q (want encfile|vault|file|env)", cfg.Provider)
	}
}

// AsStore returns p itself when it is writable, otherwise a Store whose Put
// and Delete return ErrReadOnly.
func AsStore(p Provider) Store {
	if s, ok := p.(Store); ok {
		return s
	}
	return readOnly{p}
}

// Writable reports whether p accepts Put/Delete.
func Writable(p Provider) bool {
	s, ok := p.(Store)
	if !ok {
		return false
	}
	_, ro := s.(readOnly)
	return !ro
}

type readOnly struct{ Provider }

func (r readOnly) Put(context.Context, string, []byte) error { return ErrReadOnly }
func (r readOnly) Delete(context.Context, string) error      { return ErrReadOnly }

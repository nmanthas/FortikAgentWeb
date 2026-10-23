package secrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fortik/internal/config"
)

// EnvMasterKey holds the base64 32-byte encfile master key. It takes
// precedence over secrets.master_key_file.
const EnvMasterKey = "FORTIK_MASTER_KEY"

// MasterKeySize is the AES-256 key length.
const MasterKeySize = 32

// ErrDecrypt means an encfile secret could not be authenticated: the master
// key is wrong, the file was modified, or it was copied from another name.
var ErrDecrypt = errors.New("secret decryption failed (wrong master key, tampered file, or file moved between names)")

// File format, version 1:
//
//	magic "FKS" | version byte 0x01 | nonce (12 bytes) | AES-256-GCM ciphertext+tag
//
// The GCM additional data is the 4-byte header followed by the secret name,
// so a file cannot be swapped to another name or re-labelled as another
// format version without failing authentication.
var encMagic = []byte("FKS")

const (
	encVersion1  = 0x01
	encHeaderLen = 4
	encNonceLen  = 12
	encSuffix    = ".enc"
	encTmpPrefix = ".fortik-tmp-"
	maxEncFile   = 1 << 20 // secrets are small; refuse to read anything huge
)

// EncFile is a writable secret store: one AES-256-GCM encrypted file per
// secret at <dir>/<name>.enc ('/' in names becomes subdirectories). Files are
// mode 0600 in 0700 directories and written atomically (temp file, fsync,
// rename, fsync dir). Intended for development and pilots; production uses
// Vault/OpenBao.
type EncFile struct {
	dir  string
	aead cipher.AEAD
}

var _ Store = (*EncFile)(nil)

// NewEncFile builds the store over dir with a 32-byte master key. The
// directory is created (0700) if missing.
func NewEncFile(dir string, key []byte) (*EncFile, error) {
	if dir == "" {
		return nil, errors.New("encfile: directory is required")
	}
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("encfile: master key must be %d bytes (got %d)", MasterKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("encfile: %w", err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, encNonceLen)
	if err != nil {
		return nil, fmt.Errorf("encfile: %w", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("encfile: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("encfile: create directory: %w", err)
	}
	// The directory listing reveals secret names; keep it owner-only.
	if st, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("encfile: %w", err)
	} else if !st.IsDir() {
		return nil, fmt.Errorf("encfile: %s is not a directory", abs)
	} else if st.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(abs, 0o700); err != nil {
			return nil, fmt.Errorf("encfile: restrict directory permissions: %w", err)
		}
	}
	return &EncFile{dir: abs, aead: aead}, nil
}

// OpenEncFile builds the store from config, reading the master key from
// FORTIK_MASTER_KEY or secrets.master_key_file.
func OpenEncFile(cfg config.SecretsConfig) (*EncFile, error) {
	key, err := LoadMasterKey(cfg)
	if err != nil {
		return nil, err
	}
	return NewEncFile(cfg.Dir, key)
}

// LoadMasterKey returns the 32-byte encfile master key from env
// FORTIK_MASTER_KEY (base64) or, failing that, cfg.MasterKeyFile (base64; the
// file must not be readable by group or others). It is an error if neither is
// set or the decoded key is not 32 bytes.
func LoadMasterKey(cfg config.SecretsConfig) ([]byte, error) {
	var raw, from string
	if v, ok := os.LookupEnv(EnvMasterKey); ok && strings.TrimSpace(v) != "" {
		raw, from = v, "env "+EnvMasterKey
	} else if cfg.MasterKeyFile != "" {
		st, err := os.Stat(cfg.MasterKeyFile)
		if err != nil {
			return nil, fmt.Errorf("encfile: master key file: %w", err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("encfile: master key file %s is accessible by group/others (mode %v); chmod 600 it", cfg.MasterKeyFile, st.Mode().Perm())
		}
		b, err := os.ReadFile(cfg.MasterKeyFile)
		if err != nil {
			return nil, fmt.Errorf("encfile: master key file: %w", err)
		}
		raw, from = string(b), "master_key_file "+cfg.MasterKeyFile
	} else {
		return nil, fmt.Errorf("encfile: no master key: set env %s or secrets.master_key_file to a base64 %d-byte key (e.g. openssl rand -base64 32)", EnvMasterKey, MasterKeySize)
	}
	raw = strings.TrimSpace(raw)
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		if key, err = base64.RawStdEncoding.DecodeString(raw); err != nil {
			return nil, fmt.Errorf("encfile: master key from %s is not valid base64", from)
		}
	}
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("encfile: master key from %s must decode to %d bytes (got %d)", from, MasterKeySize, len(key))
	}
	return key, nil
}

func (s *EncFile) path(name string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	p := filepath.Join(s.dir, filepath.FromSlash(name)+encSuffix)
	// Defence in depth: ValidName already guarantees containment.
	if rel, err := filepath.Rel(s.dir, p); err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", fmt.Errorf("invalid secret name %q: escapes the store directory", name)
	}
	return p, nil
}

func aad(header []byte, name string) []byte {
	out := make([]byte, 0, len(header)+len(name))
	return append(append(out, header...), name...)
}

// Get decrypts and returns the secret. A missing file is ErrNotFound; an
// authentication failure is ErrDecrypt.
func (s *EncFile) Get(ctx context.Context, name string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := s.path(name)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("encfile: read secret %s: %w", name, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxEncFile+1))
	if err != nil {
		return nil, fmt.Errorf("encfile: read secret %s: %w", name, err)
	}
	if len(b) > maxEncFile {
		return nil, fmt.Errorf("encfile: secret %s: file too large", name)
	}
	if len(b) < encHeaderLen+encNonceLen+s.aead.Overhead() || !bytes.Equal(b[:len(encMagic)], encMagic) {
		return nil, fmt.Errorf("encfile: secret %s: %w (not a Fortik encrypted secret file)", name, ErrDecrypt)
	}
	if v := b[len(encMagic)]; v != encVersion1 {
		return nil, fmt.Errorf("encfile: secret %s: unsupported format version %d", name, v)
	}
	header := b[:encHeaderLen]
	nonce := b[encHeaderLen : encHeaderLen+encNonceLen]
	plain, err := s.aead.Open(nil, nonce, b[encHeaderLen+encNonceLen:], aad(header, name))
	if err != nil {
		return nil, fmt.Errorf("encfile: secret %s: %w", name, ErrDecrypt)
	}
	return plain, nil
}

// Put encrypts value under a fresh random nonce and atomically replaces the
// secret's file.
func (s *EncFile) Put(ctx context.Context, name string, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if len(value) > maxEncFile-encHeaderLen-encNonceLen-s.aead.Overhead() {
		return fmt.Errorf("encfile: secret %s: value too large", name)
	}
	header := append(append([]byte{}, encMagic...), encVersion1)
	nonce := make([]byte, encNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("encfile: nonce: %w", err)
	}
	out := make([]byte, 0, encHeaderLen+encNonceLen+len(value)+s.aead.Overhead())
	out = append(out, header...)
	out = append(out, nonce...)
	out = s.aead.Seal(out, nonce, value, aad(header, name))

	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("encfile: create directory for %s: %w", name, err)
	}
	tmp, err := os.CreateTemp(dir, encTmpPrefix+"*")
	if err != nil {
		return fmt.Errorf("encfile: write secret %s: %w", name, err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("encfile: write secret %s: %w", name, err)
	}
	if _, err := tmp.Write(out); err != nil {
		return fmt.Errorf("encfile: write secret %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("encfile: sync secret %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("encfile: write secret %s: %w", name, err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		return fmt.Errorf("encfile: replace secret %s: %w", name, err)
	}
	committed = true
	return syncDir(dir)
}

// Delete removes the secret; a missing secret is not an error.
func (s *EncFile) Delete(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("encfile: delete secret %s: %w", name, err)
	}
	return syncDir(filepath.Dir(p))
}

// syncDir makes a rename/unlink durable. A directory that vanished (deleting
// a secret whose directory never existed) is fine.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("encfile: sync directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("encfile: sync directory: %w", err)
	}
	return nil
}

package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/authz"
	"fortik/internal/diary"
)

// touchEvery throttles last_seen_at writes (idle timeout precision).
const touchEvery = 30 * time.Second

// Session is a console login. The raw id exists only in the user's cookie.
type Session struct {
	IDHash     string    `json:"-"` // sha256 hex of the raw id (primary key)
	Email      string    `json:"email"`
	Name       string    `json:"name"`
	Roles      []string  `json:"roles"`
	AuthMethod string    `json:"auth_method"`
	CSRF       string    `json:"-"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Principal is the session's caller identity.
func (s *Session) Principal() authz.Principal {
	roles := make(map[string]bool, len(s.Roles))
	for _, r := range s.Roles {
		roles[r] = true
	}
	name := s.Name
	if name == "" {
		name = s.Email
	}
	return authz.Principal{Kind: authz.KindUser, Name: name, Email: s.Email, Roles: roles, AuthMethod: s.AuthMethod}
}

// fingerprint is a short, non-reversible session reference for the Diary.
func (s *Session) fingerprint() string { return s.IDHash[:12] }

// Authenticate resolves the request's session cookie. It returns
// ErrNoSession when there is no cookie, ErrInvalidSession when the cookie is
// malformed, unknown, expired (12h absolute / 1h idle by default) or minted
// by a login method that is no longer enabled, and any other error when the
// session store cannot be read (callers fail closed).
func (s *Service) Authenticate(ctx context.Context, r *http.Request) (*Session, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return nil, ErrNoSession
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != 32 {
		return nil, ErrInvalidSession
	}
	return s.lookup(ctx, sha256Hex(raw))
}

func (s *Service) lookup(ctx context.Context, idHash string) (*Session, error) {
	sess := &Session{IDHash: idHash}
	err := s.pool.QueryRow(ctx, `
		SELECT email, name, roles, auth_method, csrf, created_at, last_seen_at, expires_at
		FROM console_sessions WHERE id_sha256 = $1`, idHash).
		Scan(&sess.Email, &sess.Name, &sess.Roles, &sess.AuthMethod, &sess.CSRF, &sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidSession
	}
	if err != nil {
		return nil, fmt.Errorf("session lookup: %w", err)
	}
	now := s.now()
	valid := now.Before(sess.ExpiresAt) && now.Sub(sess.LastSeenAt) <= s.cfg.SessionIdleTTL
	switch sess.AuthMethod {
	case MethodDev:
		// Dev sessions follow the current dev config: a user removed from
		// it (or dev login switched off) loses access immediately, and
		// roles track the config.
		u, ok := s.devUsers[sess.Email]
		valid = valid && s.devEnabled && ok
		if ok {
			sess.Roles = sortedRoles(u.Roles)
		}
	case MethodOIDC:
		valid = valid && s.oidcOn
	default:
		valid = false
	}
	if !valid {
		if _, err := s.pool.Exec(ctx, `DELETE FROM console_sessions WHERE id_sha256 = $1`, idHash); err != nil {
			s.log.Warn("auth: could not delete expired session", "err", err)
		}
		return nil, ErrInvalidSession
	}
	if now.Sub(sess.LastSeenAt) >= touchEvery {
		if _, err := s.pool.Exec(ctx, `UPDATE console_sessions SET last_seen_at = $2 WHERE id_sha256 = $1`, idHash, now); err != nil {
			return nil, fmt.Errorf("session touch: %w", err)
		}
		sess.LastSeenAt = now
	}
	return sess, nil
}

// createSession stores a new session and records auth.login in the same
// transaction. It returns the raw cookie value (shown to nobody but the
// browser) and the session.
func (s *Service) createSession(ctx context.Context, email, name string, roles []string, method string) (string, *Session, error) {
	cookie, raw, err := randomToken(32)
	if err != nil {
		return "", nil, err
	}
	csrf, _, err := randomToken(32)
	if err != nil {
		return "", nil, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	sess := &Session{IDHash: sha256Hex(raw), Email: email, Name: name, Roles: sortedRoles(roles), AuthMethod: method,
		CSRF: csrf, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(s.cfg.SessionTTL)}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Opportunistic purge keeps the table small without a background job.
		if _, err := tx.Exec(ctx, `DELETE FROM console_sessions WHERE expires_at <= $1 OR last_seen_at < $2`,
			now, now.Add(-s.cfg.SessionIdleTTL)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO console_sessions (id_sha256, email, name, roles, auth_method, csrf, created_at, last_seen_at, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8)`,
			sess.IDHash, sess.Email, sess.Name, sess.Roles, sess.AuthMethod, sess.CSRF, now, sess.ExpiresAt); err != nil {
			return err
		}
		_, err := s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventLogin, Actor: "user:" + email, Data: map[string]any{
			"email": email, "name": name, "method": method, "roles": sess.Roles, "session": sess.fingerprint(),
			"expires_at": sess.ExpiresAt.Format(time.RFC3339)}})
		return err
	})
	if err != nil {
		return "", nil, fmt.Errorf("create session: %w", err)
	}
	return cookie, sess, nil
}

// deleteSession revokes a session and records auth.logout atomically.
func (s *Service) deleteSession(ctx context.Context, sess *Session, reason string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM console_sessions WHERE id_sha256 = $1`, sess.IDHash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil // already gone (concurrent logout/expiry)
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventLogout, Actor: "user:" + sess.Email, Data: map[string]any{
			"email": sess.Email, "method": sess.AuthMethod, "session": sess.fingerprint(), "reason": reason}})
		return err
	})
}

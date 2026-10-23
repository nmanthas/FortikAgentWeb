package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/pgsql"
)

// Limits on what one memory item may hold.
const (
	MaxContentBytes  = 256 << 10
	MaxMetadataKeys  = 64
	MaxMetadataBytes = 1024 // per key and per value
	MaxQueryLimit    = 100
	DefaultLimit     = 10
	connectTimeout   = 10 * time.Second
)

var (
	// ErrInvalid wraps every validation failure (bad namespace, content,
	// embedding of the wrong size...). Callers map it to 400.
	ErrInvalid = errors.New("invalid memory request")
	// ErrItemNotFound: no such item in the namespace.
	ErrItemNotFound = errors.New("memory item not found")
	// ErrAlreadyPromoted: the item left staging; dropping staging cannot
	// remove it any more (restore a snapshot instead).
	ErrAlreadyPromoted = errors.New("memory item already promoted to long-term memory")
	// ErrSnapshotMissing: the snapshot table no longer exists in the store.
	ErrSnapshotMissing = errors.New("memory snapshot data no longer exists in the store")
	// ErrItemReplaced: an item with the id exists but a different write
	// staged it (the undo handle's own write is gone).
	ErrItemReplaced = errors.New("memory item was written by a different action")
)

var (
	namespacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	itemIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	snapshotSuffix   = regexp.MustCompile(`^[a-z0-9]{1,40}$`)
	locationPattern  = regexp.MustCompile(`^` + DBSchema + `\.snapshot_([a-z0-9]{1,40})$`)
)

// ValidNamespace reports whether ns is a valid namespace name.
func ValidNamespace(ns string) bool { return namespacePattern.MatchString(ns) }

// ValidItemID reports whether id is a valid item id.
func ValidItemID(id string) bool { return itemIDPattern.MatchString(id) }

// SnapshotLocation returns the snapshot table (the pointer Fortik records)
// for a snapshot suffix: fortik_memory.snapshot_<suffix>.
func SnapshotLocation(suffix string) (string, error) {
	if !snapshotSuffix.MatchString(suffix) {
		return "", fmt.Errorf("%w: snapshot suffix must match %s", ErrInvalid, snapshotSuffix)
	}
	return DBSchema + ".snapshot_" + suffix, nil
}

// snapshotTable validates a location and returns the quoted table name.
func snapshotTable(location string) (string, error) {
	m := locationPattern.FindStringSubmatch(location)
	if m == nil {
		return "", fmt.Errorf("%w: snapshot location %q is not a Fortik memory snapshot", ErrInvalid, truncate(location, 80))
	}
	return pgsql.QuoteQualified(DBSchema, "snapshot_"+m[1]), nil
}

// Hit is one query result: the item and, for embedding queries, its cosine
// distance to the query vector (0 = identical).
type Hit struct {
	Item
	Distance *float64 `json:"distance,omitempty"`
}

// SearchRequest is a query against one namespace.
type SearchRequest struct {
	Namespace string
	Embedding []float32 // nearest neighbours by cosine distance
	Text      string    // full-text match ('simple' configuration)
	Limit     int       // default DefaultLimit, at most MaxQueryLimit
	// StagedOf includes the staged (not yet promoted) items this agent wrote;
	// other agents' staged items are never returned unless AllStaged.
	StagedOf  string
	AllStaged bool
	// IncludeFlagged returns flagged items too (review only; agents never
	// see flagged items).
	IncludeFlagged   bool
	IncludeEmbedding bool
}

// Promoted is one item a promotion pass moved out of staging.
type Promoted struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
	AgentID   string `json:"agent_id"`
	ActionID  string `json:"action_id,omitempty"` // the gateway write that staged it
}

// SnapshotInfo is what a snapshot copied.
type SnapshotInfo struct {
	Location string
	Count    int
	Flagged  int // flagged items in the namespace at snapshot time
	Staged   int // staged (unreviewed, not yet promoted) items at snapshot time
}

// Clean reports whether the snapshot may be used as a rollback target: no
// flagged item and no staged item nobody has reviewed yet.
func (i SnapshotInfo) Clean() bool { return i.Flagged == 0 && i.Staged == 0 }

// PGStore is the customer's Postgres + pgvector store. Tables live in schema
// fortik_memory of the customer database; Fortik connects as the
// integration's admin user. Every identifier is schema-qualified (the
// connection pins search_path to pg_catalog), and the vector type and
// distance operator are qualified with the extension's own schema.
type PGStore struct {
	pool      *pgxpool.Pool
	key       string
	dimension int // configured dimension (0 = size from the first embedding)
	// PromotionDelay is used when Write receives an item without PromoteAt.
	PromotionDelay time.Duration
	Now            func() time.Time

	initMu sync.Mutex
	ready  bool
	vtype  string // qualified vector type, e.g. "public".vector
	dist   string // qualified cosine distance operator
	dimMu  sync.RWMutex
	dims   int // current column size (0 = unsized)
}

var _ Store = (*PGStore)(nil)

// NewPGStore wraps a pool connected to the customer database as the
// integration's admin user. key is the integration key (memory:<name>),
// used in messages; dimension may be 0.
func NewPGStore(pool *pgxpool.Pool, key string, dimension int, promotionDelay time.Duration) *PGStore {
	if promotionDelay <= 0 {
		promotionDelay = 10 * time.Minute
	}
	return &PGStore{pool: pool, key: key, dimension: dimension, PromotionDelay: promotionDelay}
}

// Key is the integration key of the store (memory:<name>).
func (s *PGStore) Key() string { return s.key }

func (s *PGStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

const itemsQ = DBSchema + "." + ItemsTable

// tombstonesQ records items removed on purpose (staging undo, drop, gateway
// DELETE): a snapshot restore never brings them back. An item is identified
// by (namespace, id, created_at), so a later item that reuses the id is not
// affected.
const tombstonesQ = DBSchema + ".tombstones"

// itemCols is the fixed column list (snapshots are restored through it, so
// a snapshot taken before a future column addition still restores).
const itemCols = `id, namespace, content, embedding, metadata, agent_id, action_id, staged, flagged, flag_reason, promote_at, promoted_at, created_at`

// Init creates the vector extension (when missing), schema fortik_memory and
// the items table. It is idempotent and safe across processes; every other
// method calls it first.
func (s *PGStore) Init(ctx context.Context) error {
	s.initMu.Lock()
	defer s.initMu.Unlock()
	if s.ready {
		return nil
	}
	var vschema string
	var typmod int
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('fortik.memory.init', 0))`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS `+pgsql.QuoteIdent(DBSchema)); err != nil {
			return fmt.Errorf("create schema %s: %w", DBSchema, err)
		}
		err := tx.QueryRow(ctx, `SELECT n.nspname FROM pg_catalog.pg_extension e
			JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'vector'`).Scan(&vschema)
		if errors.Is(err, pgx.ErrNoRows) {
			// Install next to the customer's other extensions when a public
			// schema exists, otherwise in fortik_memory.
			target := DBSchema
			var hasPublic bool
			if err := tx.QueryRow(ctx, `SELECT pg_catalog.to_regnamespace('public') IS NOT NULL`).Scan(&hasPublic); err != nil {
				return err
			}
			if hasPublic {
				target = "public"
			}
			if _, err := tx.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA `+pgsql.QuoteIdent(target)); err != nil {
				return fmt.Errorf("install the vector extension (pgvector): %w", err)
			}
			vschema = target
		} else if err != nil {
			return err
		}
		vtype := pgsql.QuoteIdent(vschema) + ".vector"
		col := vtype
		if s.dimension > 0 {
			col += "(" + strconv.Itoa(s.dimension) + ")"
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+itemsQ+` (
			id          text NOT NULL,
			namespace   text NOT NULL,
			content     text NOT NULL,
			embedding   `+col+`,
			metadata    jsonb NOT NULL DEFAULT '{}',
			agent_id    text NOT NULL,
			action_id   text,
			staged      boolean NOT NULL DEFAULT true,
			flagged     boolean NOT NULL DEFAULT false,
			flag_reason text,
			promote_at  timestamptz,
			promoted_at timestamptz,
			created_at  timestamptz NOT NULL DEFAULT now(),
			hold_reason text,
			PRIMARY KEY (namespace, id)
		)`); err != nil {
			return fmt.Errorf("create %s: %w", itemsQ, err)
		}
		if err := migrateItems(ctx, tx); err != nil {
			return fmt.Errorf("migrate %s: %w", itemsQ, err)
		}
		for _, q := range []string{
			`CREATE INDEX IF NOT EXISTS items_namespace ON ` + itemsQ + ` (namespace, created_at DESC)`,
			`CREATE INDEX IF NOT EXISTS items_due ON ` + itemsQ + ` (promote_at) WHERE staged AND NOT flagged`,
			`CREATE INDEX IF NOT EXISTS items_agent_staged ON ` + itemsQ + ` (agent_id, created_at DESC) WHERE staged`,
			`CREATE TABLE IF NOT EXISTS ` + tombstonesQ + ` (
				namespace  text NOT NULL,
				id         text NOT NULL,
				created_at timestamptz NOT NULL,
				action_id  text,
				how        text NOT NULL,
				removed_at timestamptz NOT NULL DEFAULT now(),
				PRIMARY KEY (namespace, id, created_at)
			)`,
		} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return err
			}
		}
		if err := tx.QueryRow(ctx, `SELECT a.atttypmod FROM pg_catalog.pg_attribute a
			WHERE a.attrelid = $1::regclass AND a.attname = 'embedding' AND NOT a.attisdropped`, itemsQ).Scan(&typmod); err != nil {
			return err
		}
		switch {
		case s.dimension > 0 && typmod <= 0:
			if _, err := tx.Exec(ctx, `ALTER TABLE `+itemsQ+` ALTER COLUMN embedding TYPE `+col); err != nil {
				return fmt.Errorf("size the embedding column to %d: %w", s.dimension, err)
			}
			typmod = s.dimension
		case s.dimension > 0 && typmod != s.dimension:
			return fmt.Errorf("%s holds %d-dimension embeddings but the integration says %d", s.key, typmod, s.dimension)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("memory store %s: %w", s.key, err)
	}
	s.vtype = pgsql.QuoteIdent(vschema) + ".vector"
	s.dist = "OPERATOR(" + pgsql.QuoteIdent(vschema) + ".<=>)"
	s.dimMu.Lock()
	s.dims = max(typmod, 0)
	s.dimMu.Unlock()
	s.ready = true
	return nil
}

// migrateItems brings an items table created by an earlier version up to
// date (idempotent; runs under the init lock):
//   - hold_reason column (held-for-review items);
//   - primary key (namespace, id) instead of (id): ids are per namespace, so
//     an id reused in another namespace can never block a restore, and a
//     write cannot probe other namespaces for an id.
func migrateItems(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `ALTER TABLE `+itemsQ+` ADD COLUMN IF NOT EXISTS hold_reason text`); err != nil {
		return err
	}
	var conname string
	var cols []string
	err := tx.QueryRow(ctx, `SELECT c.conname, array_agg(a.attname::text ORDER BY k.ord)
		FROM pg_catalog.pg_constraint c
		CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
		JOIN pg_catalog.pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
		WHERE c.conrelid = $1::regclass AND c.contype = 'p'
		GROUP BY c.conname`, itemsQ).Scan(&conname, &cols)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		_, err = tx.Exec(ctx, `ALTER TABLE `+itemsQ+` ADD PRIMARY KEY (namespace, id)`)
		return err
	case err != nil:
		return err
	case len(cols) == 2 && cols[0] == "namespace" && cols[1] == "id":
		return nil
	}
	_, err = tx.Exec(ctx, `ALTER TABLE `+itemsQ+` DROP CONSTRAINT `+pgsql.QuoteIdent(conname)+`, ADD PRIMARY KEY (namespace, id)`)
	return err
}

// Dimension is the embedding size of the store (0 until the first embedding
// when no dimension is configured).
func (s *PGStore) Dimension() int {
	s.dimMu.RLock()
	defer s.dimMu.RUnlock()
	return s.dims
}

// sizeColumn fixes the embedding column to n dimensions on the first
// embedding of an unsized store.
func (s *PGStore) sizeColumn(ctx context.Context, n int) error {
	s.dimMu.Lock()
	defer s.dimMu.Unlock()
	if s.dims > 0 {
		return nil
	}
	var typmod int
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `LOCK TABLE `+itemsQ+` IN ACCESS EXCLUSIVE MODE`); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT a.atttypmod FROM pg_catalog.pg_attribute a
			WHERE a.attrelid = $1::regclass AND a.attname = 'embedding' AND NOT a.attisdropped`, itemsQ).Scan(&typmod); err != nil {
			return err
		}
		if typmod > 0 {
			return nil // another process sized it
		}
		if _, err := tx.Exec(ctx, `ALTER TABLE `+itemsQ+` ALTER COLUMN embedding TYPE `+s.vtype+`(`+strconv.Itoa(n)+`)`); err != nil {
			return err
		}
		typmod = n
		return nil
	})
	if err != nil {
		return fmt.Errorf("memory store %s: size embedding column: %w", s.key, err)
	}
	s.dims = typmod
	return nil
}

// nsLock serialises writes against restores of one namespace: writers and
// snapshots share it, a restore takes it exclusively.
func nsLock(ctx context.Context, tx pgx.Tx, namespace string, exclusive bool) error {
	fn := "pg_advisory_xact_lock_shared"
	if exclusive {
		fn = "pg_advisory_xact_lock"
	}
	_, err := tx.Exec(ctx, `SELECT pg_catalog.`+fn+`(pg_catalog.hashtextextended('fortik.memory.ns:' || $1, 0))`, namespace)
	return err
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// ValidateItem checks an item before it is written.
func ValidateItem(it Item) error {
	switch {
	case !ValidNamespace(it.Namespace):
		return invalidf("namespace must match %s", namespacePattern)
	case it.ID != "" && !ValidItemID(it.ID):
		return invalidf("id must match %s", itemIDPattern)
	case it.AgentID == "":
		return invalidf("agent_id is required")
	case it.Content == "":
		return invalidf("content is required")
	case len(it.Content) > MaxContentBytes:
		return invalidf("content exceeds %d bytes", MaxContentBytes)
	case !utf8.ValidString(it.Content) || strings.ContainsRune(it.Content, 0):
		return invalidf("content must be UTF-8 text without NUL bytes")
	case len(it.Metadata) > MaxMetadataKeys:
		return invalidf("at most %d metadata keys", MaxMetadataKeys)
	}
	for k, v := range it.Metadata {
		if k == "" || len(k) > MaxMetadataBytes || len(v) > MaxMetadataBytes || strings.ContainsRune(k+v, 0) || !utf8.ValidString(k+v) {
			return invalidf("metadata keys must be non-empty and keys/values at most %d bytes of UTF-8 text", MaxMetadataBytes)
		}
	}
	return validateEmbedding(it.Embedding)
}

func validateEmbedding(e []float32) error {
	if len(e) > MaxDimension {
		return invalidf("embedding has more than %d dimensions", MaxDimension)
	}
	for _, f := range e {
		if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
			return invalidf("embedding values must be finite numbers")
		}
	}
	return nil
}

// vectorText renders an embedding in pgvector's text format.
func vectorText(e []float32) string {
	var b strings.Builder
	b.Grow(len(e) * 8)
	b.WriteByte('[')
	for i, f := range e {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatFloat(float64(f), 'g', -1, 32))
	}
	b.WriteByte(']')
	return b.String()
}

func parseVector(s string) ([]float32, error) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return nil, fmt.Errorf("malformed vector")
	}
	body := s[1 : len(s)-1]
	if body == "" {
		return []float32{}, nil
	}
	parts := strings.Split(body, ",")
	out := make([]float32, len(parts))
	for i, p := range parts {
		f, err := strconv.ParseFloat(strings.TrimSpace(p), 32)
		if err != nil {
			return nil, err
		}
		out[i] = float32(f)
	}
	return out, nil
}

// checkDims ensures the embedding matches the store's dimension, sizing an
// unsized store from the first embedding.
func (s *PGStore) checkDims(ctx context.Context, e []float32, sizeIfUnset bool) error {
	if len(e) == 0 {
		return nil
	}
	d := s.Dimension()
	if d == 0 {
		if !sizeIfUnset {
			return nil // no embedding stored yet: nothing to compare against
		}
		if err := s.sizeColumn(ctx, len(e)); err != nil {
			return err
		}
		d = s.Dimension()
	}
	if len(e) != d {
		return invalidf("embedding has %d dimensions; store %s holds %d-dimension embeddings", len(e), s.key, d)
	}
	return nil
}

// Write stores an item in staging (Staged=true). See WriteFor.
func (s *PGStore) Write(ctx context.Context, it Item) (Item, error) { return s.WriteFor(ctx, it, "") }

// WriteFor stores an item in staging and records the Fortik action that
// wrote it. An empty ID is generated; PromoteAt defaults to now +
// PromotionDelay. Writes are never visible to other agents until promoted.
func (s *PGStore) WriteFor(ctx context.Context, it Item, actionID string) (Item, error) {
	if err := ValidateItem(it); err != nil {
		return Item{}, err
	}
	if err := s.Init(ctx); err != nil {
		return Item{}, err
	}
	if err := s.checkDims(ctx, it.Embedding, true); err != nil {
		return Item{}, err
	}
	if it.ID == "" {
		it.ID = action.NewID("mem")
	}
	switch {
	case it.HoldReason != "":
		// Held for review: no promotion time until a review window opens.
		it.PromoteAt = nil
	case it.PromoteAt == nil:
		t := s.now().Add(s.PromotionDelay)
		it.PromoteAt = &t
	}
	if it.Metadata == nil {
		it.Metadata = map[string]string{}
	}
	meta, err := json.Marshal(it.Metadata)
	if err != nil {
		return Item{}, invalidf("metadata: %v", err)
	}
	var vec *string
	if len(it.Embedding) > 0 {
		v := vectorText(it.Embedding)
		vec = &v
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := nsLock(ctx, tx, it.Namespace, false); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO `+itemsQ+` (id, namespace, content, embedding, metadata, agent_id, action_id, staged, flagged, promote_at, hold_reason)
			VALUES ($1, $2, $3, $4::text::`+s.vtype+`, $5, $6, NULLIF($7, ''), true, false, $8, NULLIF($9, ''))
			RETURNING created_at`, it.ID, it.Namespace, it.Content, vec, meta, it.AgentID, actionID, it.PromoteAt, truncate(it.HoldReason, 1000)).Scan(&it.CreatedAt)
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505":
				return Item{}, invalidf("an item with id %s already exists in namespace %s", it.ID, it.Namespace)
			case "22000", "22023":
				return Item{}, invalidf("embedding rejected by the store: %s", pgErr.Message)
			}
		}
		return Item{}, fmt.Errorf("memory store %s: write: %w", s.key, err)
	}
	it.Staged, it.Flagged, it.ActionID = true, false, actionID
	return it, nil
}

// Query implements Store. includeStaged returns every agent's staged items
// (review use); agent queries go through Search with StagedOf.
func (s *PGStore) Query(ctx context.Context, namespace string, embedding []float32, text string, limit int, includeStaged bool) ([]Item, error) {
	hits, err := s.Search(ctx, SearchRequest{Namespace: namespace, Embedding: embedding, Text: text, Limit: limit, AllStaged: includeStaged})
	if err != nil {
		return nil, err
	}
	out := make([]Item, len(hits))
	for i, h := range hits {
		out[i] = h.Item
	}
	return out, nil
}

// Search queries one namespace: nearest neighbours by cosine distance when
// an embedding is given (optionally filtered by text), full-text match when
// only text is given, newest first otherwise. Promoted, unflagged items are
// always eligible; staged items only for their writer (StagedOf) or with
// AllStaged.
func (s *PGStore) Search(ctx context.Context, q SearchRequest) ([]Hit, error) {
	if !ValidNamespace(q.Namespace) {
		return nil, invalidf("namespace must match %s", namespacePattern)
	}
	if err := validateEmbedding(q.Embedding); err != nil {
		return nil, err
	}
	if len(q.Text) > 4096 || strings.ContainsRune(q.Text, 0) || !utf8.ValidString(q.Text) {
		return nil, invalidf("text must be at most 4096 bytes of UTF-8 text")
	}
	if q.Limit <= 0 {
		q.Limit = DefaultLimit
	}
	if q.Limit > MaxQueryLimit {
		q.Limit = MaxQueryLimit
	}
	if err := s.Init(ctx); err != nil {
		return nil, err
	}
	if err := s.checkDims(ctx, q.Embedding, false); err != nil {
		return nil, err
	}
	if len(q.Embedding) > 0 && s.Dimension() == 0 {
		return []Hit{}, nil // nothing has an embedding yet
	}
	args := []any{q.Namespace, q.AllStaged, q.StagedOf, q.IncludeFlagged, q.IncludeEmbedding}
	where := `namespace = $1 AND (NOT staged OR $2 OR agent_id = $3) AND (NOT flagged OR $4)`
	dist := `NULL::float8`
	order := `created_at DESC, id`
	if q.Text != "" {
		args = append(args, q.Text)
		where += fmt.Sprintf(` AND pg_catalog.to_tsvector('pg_catalog.simple', content) @@ pg_catalog.plainto_tsquery('pg_catalog.simple', $%d)`, len(args))
		order = fmt.Sprintf(`pg_catalog.ts_rank(pg_catalog.to_tsvector('pg_catalog.simple', content), pg_catalog.plainto_tsquery('pg_catalog.simple', $%d)) DESC, created_at DESC, id`, len(args))
	}
	if len(q.Embedding) > 0 {
		args = append(args, vectorText(q.Embedding))
		dist = fmt.Sprintf(`(embedding %s $%d::text::%s)::float8`, s.dist, len(args), s.vtype)
		where += ` AND embedding IS NOT NULL`
		order = `distance, id`
	}
	args = append(args, q.Limit)
	sql := `SELECT id, namespace, content, CASE WHEN $5 THEN embedding::text END, metadata, agent_id, staged, flagged, created_at, promote_at, ` +
		dist + ` AS distance FROM ` + itemsQ + ` WHERE ` + where + ` ORDER BY ` + order + fmt.Sprintf(` LIMIT $%d`, len(args))
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("memory store %s: query: %w", s.key, err)
	}
	defer rows.Close()
	out := []Hit{}
	for rows.Next() {
		var h Hit
		var vec *string
		var meta []byte
		if err := rows.Scan(&h.ID, &h.Namespace, &h.Content, &vec, &meta, &h.AgentID, &h.Staged, &h.Flagged, &h.CreatedAt, &h.PromoteAt, &h.Distance); err != nil {
			return nil, err
		}
		if err := fill(&h.Item, vec, meta); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func fill(it *Item, vec *string, meta []byte) error {
	if vec != nil {
		e, err := parseVector(*vec)
		if err != nil {
			return fmt.Errorf("memory store: stored embedding: %w", err)
		}
		it.Embedding = e
	}
	if len(meta) > 0 {
		m := map[string]any{}
		if err := json.Unmarshal(meta, &m); err != nil {
			return fmt.Errorf("memory store: stored metadata: %w", err)
		}
		it.Metadata = make(map[string]string, len(m))
		for k, v := range m {
			if s, ok := v.(string); ok {
				it.Metadata[k] = s
			} else {
				b, _ := json.Marshal(v)
				it.Metadata[k] = string(b)
			}
		}
		if len(it.Metadata) == 0 {
			it.Metadata = nil
		}
	}
	return nil
}

// itemRet is the column list scanItem reads (without the embedding).
const itemRet = `id, namespace, content, NULL::text, metadata, agent_id, staged, flagged, created_at, promote_at, coalesce(action_id, ''), coalesce(hold_reason, '')`

const selectItem = `SELECT ` + itemRet + ` FROM ` + itemsQ

func scanItem(row pgx.Row) (Item, error) {
	var it Item
	var vec *string
	var meta []byte
	if err := row.Scan(&it.ID, &it.Namespace, &it.Content, &vec, &meta, &it.AgentID, &it.Staged, &it.Flagged, &it.CreatedAt, &it.PromoteAt,
		&it.ActionID, &it.HoldReason); err != nil {
		return Item{}, err
	}
	return it, fill(&it, vec, meta)
}

// Get returns one item (without its embedding).
func (s *PGStore) Get(ctx context.Context, namespace, id string) (Item, error) {
	if err := checkRef(namespace, id); err != nil {
		return Item{}, err
	}
	if err := s.Init(ctx); err != nil {
		return Item{}, err
	}
	it, err := scanItem(s.pool.QueryRow(ctx, selectItem+` WHERE namespace = $1 AND id = $2`, namespace, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Item{}, ErrItemNotFound
	}
	if err != nil {
		return Item{}, fmt.Errorf("memory store %s: get: %w", s.key, err)
	}
	return it, nil
}

func checkRef(namespace, id string) error {
	if !ValidNamespace(namespace) {
		return invalidf("namespace must match %s", namespacePattern)
	}
	if !ValidItemID(id) {
		return invalidf("item id must match %s", itemIDPattern)
	}
	return nil
}

// Removal kinds recorded in the tombstones table.
const (
	RemovedByDelete = "deleted"   // gateway DELETE (approved)
	RemovedByDrop   = "dropped"   // POST /v1/memory/items/.../drop
	RemovedByUndo   = "undo"      // staging undo (memory_staging)
	removedByOther  = "store_api" // Delete/DropStaged through the Store interface
)

// Delete removes an item, staged or promoted. Not reversible: the item is
// tombstoned, so restoring a snapshot does not bring it back either.
func (s *PGStore) Delete(ctx context.Context, namespace, id string) error {
	_, err := s.remove(ctx, namespace, id, false, "", removedByOther)
	return err
}

// DeleteItem is Delete returning what was removed (gateway DELETE).
func (s *PGStore) DeleteItem(ctx context.Context, namespace, id string) (Item, error) {
	return s.remove(ctx, namespace, id, false, "", RemovedByDelete)
}

// DropStaged removes a staged item. A promoted item is not touched:
// ErrAlreadyPromoted.
func (s *PGStore) DropStaged(ctx context.Context, namespace, id string) error {
	_, err := s.remove(ctx, namespace, id, true, "", removedByOther)
	return err
}

// DropStagedItem is DropStaged returning what was removed (API drop).
func (s *PGStore) DropStagedItem(ctx context.Context, namespace, id string) (Item, error) {
	return s.remove(ctx, namespace, id, true, "", RemovedByDrop)
}

// DropStagedWrite is the undo of the staged write actionID: it drops the
// item only when that write staged it. An item with the id that another
// write staged is left alone (ErrItemReplaced).
func (s *PGStore) DropStagedWrite(ctx context.Context, namespace, id, actionID string) (Item, error) {
	if actionID == "" {
		return Item{}, fmt.Errorf("%w: no action id", ErrItemReplaced)
	}
	return s.remove(ctx, namespace, id, true, actionID, RemovedByUndo)
}

// remove deletes one item and tombstones it, in one transaction. With
// actionID set, only the item that write staged qualifies.
func (s *PGStore) remove(ctx context.Context, namespace, id string, stagedOnly bool, actionID, how string) (Item, error) {
	if err := checkRef(namespace, id); err != nil {
		return Item{}, err
	}
	if err := s.Init(ctx); err != nil {
		return Item{}, err
	}
	var it Item
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := nsLock(ctx, tx, namespace, false); err != nil {
			return err
		}
		q := `DELETE FROM ` + itemsQ + ` WHERE namespace = $1 AND id = $2 AND ($3 = '' OR action_id = $3)`
		if stagedOnly {
			q += ` AND staged`
		}
		var err error
		it, err = scanItem(tx.QueryRow(ctx, q+` RETURNING `+itemRet, namespace, id, actionID))
		if err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO `+tombstonesQ+` (namespace, id, created_at, action_id, how)
				VALUES ($1, $2, $3, NULLIF($4, ''), $5) ON CONFLICT DO NOTHING`, it.Namespace, it.ID, it.CreatedAt, it.ActionID, how)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var staged bool
		var writer string
		err = tx.QueryRow(ctx, `SELECT staged, coalesce(action_id, '') FROM `+itemsQ+` WHERE namespace = $1 AND id = $2`, namespace, id).Scan(&staged, &writer)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrItemNotFound
		case err != nil:
			return err
		case actionID != "" && writer != actionID:
			return ErrItemReplaced
		case stagedOnly && !staged:
			return ErrAlreadyPromoted
		}
		return ErrItemNotFound
	})
	if err != nil {
		if errors.Is(err, ErrItemNotFound) || errors.Is(err, ErrAlreadyPromoted) || errors.Is(err, ErrItemReplaced) {
			return Item{}, err
		}
		return Item{}, fmt.Errorf("memory store %s: delete: %w", s.key, err)
	}
	return it, nil
}

// Promote implements Store: every due, unflagged staged item goes live.
func (s *PGStore) Promote(ctx context.Context, now time.Time) (int, error) {
	p, err := s.PromoteDue(ctx, now, nil)
	return len(p), err
}

// PromoteDue moves due, unflagged staged items out of staging, except those
// written by excludeAgents (access staging_only or none). Held items (no
// promote_at) are never due: see OpenReviewWindows.
func (s *PGStore) PromoteDue(ctx context.Context, now time.Time, excludeAgents []string) ([]Promoted, error) {
	if err := s.Init(ctx); err != nil {
		return nil, err
	}
	if excludeAgents == nil {
		excludeAgents = []string{} // NULL would exclude everything (NOT (x = ANY(NULL)) is NULL)
	}
	rows, err := s.pool.Query(ctx, `UPDATE `+itemsQ+` SET staged = false, promoted_at = $1
		WHERE staged AND NOT flagged AND promote_at <= $1 AND NOT (agent_id = ANY($2::text[]))
		RETURNING id, namespace, agent_id, coalesce(action_id, '')`, now, excludeAgents)
	if err != nil {
		return nil, fmt.Errorf("memory store %s: promote: %w", s.key, err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Promoted])
	if err != nil {
		return nil, fmt.Errorf("memory store %s: promote: %w", s.key, err)
	}
	return out, nil
}

// Held is a staged item held for review (or given a review window).
type Held struct {
	ID         string     `json:"id"`
	Namespace  string     `json:"namespace"`
	AgentID    string     `json:"agent_id"`
	ActionID   string     `json:"action_id,omitempty"`
	HoldReason string     `json:"hold_reason"`
	PromoteAt  *time.Time `json:"promote_at,omitempty"`
}

// OpenReviewWindows gives every held (staged, unflagged, no promote_at) item
// whose writer is not in excludeAgents a fresh review window: promote_at =
// promoteAt. Such an item is promoted only after that window, unless it is
// flagged or dropped meanwhile.
func (s *PGStore) OpenReviewWindows(ctx context.Context, promoteAt time.Time, excludeAgents []string) ([]Held, error) {
	if err := s.Init(ctx); err != nil {
		return nil, err
	}
	if excludeAgents == nil {
		excludeAgents = []string{}
	}
	rows, err := s.pool.Query(ctx, `UPDATE `+itemsQ+` SET promote_at = $1
		WHERE staged AND NOT flagged AND promote_at IS NULL AND NOT (agent_id = ANY($2::text[]))
		RETURNING id, namespace, agent_id, coalesce(action_id, ''), coalesce(hold_reason, ''), promote_at`, promoteAt, excludeAgents)
	if err != nil {
		return nil, fmt.Errorf("memory store %s: open review windows: %w", s.key, err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Held])
	if err != nil {
		return nil, fmt.Errorf("memory store %s: open review windows: %w", s.key, err)
	}
	return out, nil
}

// HoldWrite holds the staged item that write actionID staged for review (no
// promote_at): its writer's access was not full when it was written. It
// reports whether an item was held.
func (s *PGStore) HoldWrite(ctx context.Context, namespace, id, actionID, reason string) (bool, error) {
	if err := checkRef(namespace, id); err != nil {
		return false, err
	}
	if err := s.Init(ctx); err != nil {
		return false, err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE `+itemsQ+` SET promote_at = NULL, hold_reason = $4
		WHERE namespace = $1 AND id = $2 AND action_id = $3 AND staged`, namespace, id, actionID, truncate(reason, 1000))
	if err != nil {
		return false, fmt.Errorf("memory store %s: hold: %w", s.key, err)
	}
	return tag.RowsAffected() == 1, nil
}

// HeldBy lists an agent's unflagged staged items that are (or were) held for
// review, newest first, without embeddings.
func (s *PGStore) HeldBy(ctx context.Context, agentID string, limit int) ([]Item, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if err := s.Init(ctx); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, selectItem+` WHERE agent_id = $1 AND staged AND NOT flagged AND hold_reason IS NOT NULL
		ORDER BY created_at DESC, id LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("memory store %s: held items: %w", s.key, err)
	}
	defer rows.Close()
	out := []Item{}
	for rows.Next() {
		it, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// Flag implements Store: the item is never promoted and agents no longer see it.
func (s *PGStore) Flag(ctx context.Context, namespace, id, reason string) error {
	_, err := s.FlagItem(ctx, namespace, id, reason)
	return err
}

// FlagItem flags an item and returns it.
func (s *PGStore) FlagItem(ctx context.Context, namespace, id, reason string) (Item, error) {
	if err := checkRef(namespace, id); err != nil {
		return Item{}, err
	}
	if err := s.Init(ctx); err != nil {
		return Item{}, err
	}
	it, err := scanItem(s.pool.QueryRow(ctx, `UPDATE `+itemsQ+` SET flagged = true, flag_reason = $3
		WHERE namespace = $1 AND id = $2
		RETURNING `+itemRet, namespace, id, truncate(reason, 1000)))
	if errors.Is(err, pgx.ErrNoRows) {
		return Item{}, ErrItemNotFound
	}
	if err != nil {
		return Item{}, fmt.Errorf("memory store %s: flag: %w", s.key, err)
	}
	return it, nil
}

// StagedBy lists the staged items an agent wrote, newest first (all
// namespaces), without embeddings.
func (s *PGStore) StagedBy(ctx context.Context, agentID string, limit int) ([]Item, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if err := s.Init(ctx); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, selectItem+` WHERE agent_id = $1 AND staged ORDER BY created_at DESC, id LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("memory store %s: staged items: %w", s.key, err)
	}
	defer rows.Close()
	out := []Item{}
	for rows.Next() {
		it, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// Namespaces lists the namespaces that hold items.
func (s *PGStore) Namespaces(ctx context.Context) ([]string, error) {
	if err := s.Init(ctx); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT namespace FROM `+itemsQ+` ORDER BY namespace`)
	if err != nil {
		return nil, fmt.Errorf("memory store %s: namespaces: %w", s.key, err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Snapshot implements Store with a generated location.
func (s *PGStore) Snapshot(ctx context.Context, namespace string) (string, int, error) {
	loc, err := SnapshotLocation(strings.ToLower(strings.TrimPrefix(action.NewID("s"), "s_")))
	if err != nil {
		return "", 0, err
	}
	info, err := s.SnapshotTo(ctx, namespace, loc)
	return info.Location, info.Count, err
}

// SnapshotTo copies every item of the namespace (staged and flagged ones
// included, so a restore is exact) into a new table at location, in one
// transaction.
func (s *PGStore) SnapshotTo(ctx context.Context, namespace, location string) (SnapshotInfo, error) {
	if !ValidNamespace(namespace) {
		return SnapshotInfo{}, invalidf("namespace must match %s", namespacePattern)
	}
	table, err := snapshotTable(location)
	if err != nil {
		return SnapshotInfo{}, err
	}
	if err := s.Init(ctx); err != nil {
		return SnapshotInfo{}, err
	}
	var info SnapshotInfo
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := nsLock(ctx, tx, namespace, false); err != nil {
			return err
		}
		info, err = copyNamespace(ctx, tx, namespace, location, table)
		return err
	})
	if err != nil {
		return SnapshotInfo{}, fmt.Errorf("memory store %s: snapshot %s: %w", s.key, namespace, err)
	}
	return info, nil
}

// copyNamespace copies the namespace's items into a new snapshot table. The
// caller holds the namespace lock in tx.
func copyNamespace(ctx context.Context, tx pgx.Tx, namespace, location, table string) (SnapshotInfo, error) {
	info := SnapshotInfo{Location: location}
	if _, err := tx.Exec(ctx, `CREATE TABLE `+table+` (LIKE `+itemsQ+` INCLUDING DEFAULTS)`); err != nil {
		return info, err
	}
	if _, err := tx.Exec(ctx, `COMMENT ON TABLE `+table+` IS `+pgsql.QuoteLiteral("Fortik memory snapshot of namespace "+namespace)); err != nil {
		return info, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+table+` (`+itemCols+`) SELECT `+itemCols+` FROM `+itemsQ+` WHERE namespace = $1`, namespace); err != nil {
		return info, err
	}
	err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE flagged), count(*) FILTER (WHERE staged) FROM `+table).
		Scan(&info.Count, &info.Flagged, &info.Staged)
	return info, err
}

// Restore replaces the namespace's contents with the snapshot's, in one
// transaction (writers to the namespace wait). It returns the number of
// items restored. See RestoreNamespace.
func (s *PGStore) Restore(ctx context.Context, namespace, location string) (int, error) {
	out, err := s.RestoreNamespace(ctx, RestoreSpec{Namespace: namespace, Location: location})
	return out.Restored, err
}

// RestoreSpec is one namespace restore.
type RestoreSpec struct {
	Namespace string
	Location  string // the snapshot to restore
	// BackupLocation, when set, receives a copy of the namespace as it stands
	// right before the restore, taken in the same transaction under the
	// exclusive namespace lock (no write can land in between).
	BackupLocation string
	// CleanOnly refuses a snapshot that holds a flagged or a staged item
	// (ErrSnapshotNotClean), whatever its pointer says.
	CleanOnly bool
	// HoldReason is recorded on every staged, unflagged item the restore
	// brings back: such an item is held for review (no promote_at) instead
	// of being promoted at its old, likely past, promote_at.
	HoldReason string
}

// RestoreOutcome is what RestoreNamespace did.
type RestoreOutcome struct {
	Restored int
	Backup   SnapshotInfo // zero without BackupLocation
	// Skipped are ids in the snapshot that were removed on purpose since
	// (undo, drop, DELETE): they are not restored.
	Skipped []string
	// Held are the staged items the restore brought back, held for review.
	Held []Held
	// RemovedWrites are the action ids of staged writes the restore removed
	// from the namespace (their staging undo no longer applies).
	RemovedWrites []string
}

// RestoreNamespace replaces the namespace with the snapshot's contents in one
// transaction under the exclusive namespace lock: optional backup copy,
// delete, insert (tombstoned items excepted), hold of restored staged items.
// Any failure rolls everything back, the backup table included.
func (s *PGStore) RestoreNamespace(ctx context.Context, spec RestoreSpec) (RestoreOutcome, error) {
	var out RestoreOutcome
	if !ValidNamespace(spec.Namespace) {
		return out, invalidf("namespace must match %s", namespacePattern)
	}
	table, err := snapshotTable(spec.Location)
	if err != nil {
		return out, err
	}
	backup := ""
	if spec.BackupLocation != "" {
		if backup, err = snapshotTable(spec.BackupLocation); err != nil {
			return out, err
		}
	}
	if spec.HoldReason == "" {
		spec.HoldReason = "restored from a snapshot: held for review"
	}
	if err := s.Init(ctx); err != nil {
		return out, err
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		out = RestoreOutcome{}
		ns := spec.Namespace
		if err := nsLock(ctx, tx, ns, true); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrSnapshotMissing
		}
		var foreign, flagged, staged int
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE namespace <> $1), count(*) FILTER (WHERE flagged), count(*) FILTER (WHERE staged)
			FROM `+table, ns).Scan(&foreign, &flagged, &staged); err != nil {
			return err
		}
		if foreign > 0 {
			return invalidf("snapshot %s holds items of another namespace", spec.Location)
		}
		if spec.CleanOnly && (flagged > 0 || staged > 0) {
			return fmt.Errorf("%w: the snapshot holds %d flagged and %d staged (unreviewed) items", ErrSnapshotNotClean, flagged, staged)
		}
		if backup != "" {
			var err error
			if out.Backup, err = copyNamespace(ctx, tx, ns, spec.BackupLocation, backup); err != nil {
				return fmt.Errorf("pre-restore copy: %w", err)
			}
		}
		const removed = `EXISTS (SELECT 1 FROM ` + tombstonesQ + ` t WHERE t.namespace = s.namespace AND t.id = s.id AND t.created_at = s.created_at)`
		const notRemoved = `NOT ` + removed
		rows, err := tx.Query(ctx, `SELECT s.id FROM `+table+` s WHERE s.namespace = $1 AND `+removed+` ORDER BY s.id`, ns)
		if err != nil {
			return err
		}
		if out.Skipped, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return err
		}
		// Staged writes in the namespace now that the restore does not bring
		// back (the same item = same id and created_at).
		rows, err = tx.Query(ctx, `SELECT i.action_id FROM `+itemsQ+` i WHERE i.namespace = $1 AND i.staged AND i.action_id IS NOT NULL
			AND NOT EXISTS (SELECT 1 FROM `+table+` s WHERE s.namespace = i.namespace AND s.id = i.id AND s.created_at = i.created_at AND `+notRemoved+`)
			ORDER BY i.action_id`, ns)
		if err != nil {
			return err
		}
		if out.RemovedWrites, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM `+itemsQ+` WHERE namespace = $1`, ns); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO `+itemsQ+` (`+itemCols+`) SELECT `+itemCols+` FROM `+table+` s WHERE s.namespace = $1 AND `+notRemoved, ns)
		if err != nil {
			return err
		}
		out.Restored = int(tag.RowsAffected())
		rows, err = tx.Query(ctx, `UPDATE `+itemsQ+` SET promote_at = NULL, hold_reason = $2
			WHERE namespace = $1 AND staged AND NOT flagged
			RETURNING id, namespace, agent_id, coalesce(action_id, ''), hold_reason, promote_at`, ns, truncate(spec.HoldReason, 1000))
		if err != nil {
			return err
		}
		out.Held, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Held])
		return err
	})
	if err != nil {
		if errors.Is(err, ErrSnapshotMissing) || errors.Is(err, ErrInvalid) || errors.Is(err, ErrSnapshotNotClean) {
			return RestoreOutcome{}, err
		}
		return RestoreOutcome{}, fmt.Errorf("memory store %s: restore %s: %w", s.key, spec.Namespace, err)
	}
	return out, nil
}

// DropSnapshot removes a snapshot table (retention purge). Dropping a
// snapshot that no longer exists is not an error.
func (s *PGStore) DropSnapshot(ctx context.Context, location string) error {
	table, err := snapshotTable(location)
	if err != nil {
		return err
	}
	if err := s.Init(ctx); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `DROP TABLE IF EXISTS `+table); err != nil {
		return fmt.Errorf("memory store %s: drop snapshot: %w", s.key, err)
	}
	return nil
}

// SnapshotContains reports whether the snapshot at location holds item id
// (a snapshot whose table is gone holds nothing).
func (s *PGStore) SnapshotContains(ctx context.Context, location, id string) (bool, error) {
	table, err := snapshotTable(location)
	if err != nil {
		return false, err
	}
	if err := s.Init(ctx); err != nil {
		return false, err
	}
	var ok bool
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			return err
		}
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+table+` WHERE id = $1)`, id).Scan(&ok)
	})
	if err != nil {
		return false, fmt.Errorf("memory store %s: inspect snapshot: %w", s.key, err)
	}
	return ok, nil
}

// digestSQL fingerprints a namespace's state: which items exist and whether
// each is staged or flagged (items are never edited in place).
const digestSQL = `SELECT count(*), coalesce(pg_catalog.md5(pg_catalog.string_agg(id || ':' || staged::text || ':' || flagged::text, ',' ORDER BY id)), '')
	FROM %s WHERE namespace = $1`

// SameContents reports whether the namespace still holds exactly what the
// snapshot at location holds (so a new automatic snapshot would be a copy).
func (s *PGStore) SameContents(ctx context.Context, namespace, location string) (bool, error) {
	table, err := snapshotTable(location)
	if err != nil {
		return false, err
	}
	if err := s.Init(ctx); err != nil {
		return false, err
	}
	same := false
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			return err
		}
		var n1, n2 int
		var d1, d2 string
		if err := tx.QueryRow(ctx, fmt.Sprintf(digestSQL, itemsQ), namespace).Scan(&n1, &d1); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, fmt.Sprintf(digestSQL, table), namespace).Scan(&n2, &d2); err != nil {
			return err
		}
		same = n1 == n2 && d1 == d2
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("memory store %s: compare snapshot: %w", s.key, err)
	}
	return same, nil
}

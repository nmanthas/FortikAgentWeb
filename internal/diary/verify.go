package diary

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Report is the result of verifying a contiguous chain segment.
type Report struct {
	OK        bool     `json:"ok"`
	Checked   int64    `json:"checked"`
	FirstSeq  int64    `json:"first_seq"`
	LastSeq   int64    `json:"last_seq"`
	LastHash  string   `json:"last_hash"`
	HeadSeq   int64    `json:"head_seq,omitempty"`
	HeadHash  string   `json:"head_hash,omitempty"`
	Problems  []string `json:"problems,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Truncated bool     `json:"truncated,omitempty"` // problems list capped
}

const maxProblems = 50

func (r *Report) problem(format string, a ...any) {
	r.OK = false
	if len(r.Problems) >= maxProblems {
		r.Truncated = true
		return
	}
	r.Problems = append(r.Problems, fmt.Sprintf(format, a...))
}

// VerifyEntries checks a contiguous, seq-ordered slice: every hash recomputes,
// every prev_hash links to the previous entry, seq has no gaps, and each body
// agrees with its row columns. expectPrev is the prev_hash the first entry
// must carry ("" = accept whatever it carries).
func VerifyEntries(entries []Entry, expectPrev string) Report {
	r := Report{OK: true}
	prev := expectPrev
	var lastSeq int64
	for i, e := range entries {
		if i == 0 {
			r.FirstSeq = e.Seq
		} else if e.Seq != lastSeq+1 {
			r.problem("seq gap: %d follows %d", e.Seq, lastSeq)
		}
		if prev != "" && e.PrevHash != prev {
			r.problem("seq %d: prev_hash %s does not link to previous hash %s", e.Seq, short(e.PrevHash), short(prev))
		}
		if got := ComputeHash(e.PrevHash, e.BodyJSON); got != e.Hash {
			r.problem("seq %d: hash mismatch (stored %s, recomputed %s): body or prev_hash altered", e.Seq, short(e.Hash), short(got))
		}
		var b struct {
			Seq       int64  `json:"seq"`
			TS        string `json:"ts"`
			AgentID   string `json:"agent_id"`
			EventType string `json:"event_type"`
			Actor     string `json:"actor"`
		}
		if err := json.Unmarshal([]byte(e.BodyJSON), &b); err != nil {
			r.problem("seq %d: body is not valid JSON", e.Seq)
		} else {
			ts, _ := time.Parse(time.RFC3339Nano, b.TS)
			if b.Seq != e.Seq || b.EventType != e.EventType || b.AgentID != e.AgentID || b.Actor != e.Actor || !ts.Equal(e.TS) {
				r.problem("seq %d: row columns disagree with hashed body", e.Seq)
			}
		}
		prev = e.Hash
		lastSeq = e.Seq
		r.Checked++
	}
	r.LastSeq = lastSeq
	r.LastHash = prev
	return r
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// VerifyChain verifies the chain from genesis up to the head as it was when
// verification started (appends that commit meanwhile are not "tampering"),
// checks the head row matches that entry (detects tail truncation), and
// checks every sealed daily root: the entry at its last_seq must carry its
// root_hash, and its Ed25519 signature must verify (against the pinned key
// when one is configured). A rewritten-and-rehashed chain therefore fails at
// the first sealed day it touches.
func (d *Diary) VerifyChain(ctx context.Context) (Report, error) {
	total := Report{OK: true}
	// Head and the highest stored seq in ONE statement snapshot: an append
	// writes both in one transaction, so max(seq) > head.seq only happens if
	// the head row was rewound to hide tail entries.
	var headSeq, maxSeq int64
	var headHash string
	if err := d.pool.QueryRow(ctx, `SELECT h.seq, h.hash, (SELECT COALESCE(max(seq), 0) FROM diary) FROM diary_head h WHERE h.id`).
		Scan(&headSeq, &headHash, &maxSeq); err != nil {
		return total, err
	}
	total.HeadSeq, total.HeadHash = headSeq, headHash
	if maxSeq > headSeq {
		total.problem("entries exist beyond the head (max seq %d > head seq %d): head row rewound to hide entries", maxSeq, headSeq)
	}
	prev := GenesisHash
	var after int64
	hashAt := map[int64]string{0: GenesisHash}
	roots, err := d.roots(ctx)
	if err != nil {
		return total, err
	}
	sealedEvents := map[string]map[string]any{} // day -> data of the diary.root_sealed event
	want := map[int64]bool{}
	for _, r := range roots {
		want[r.Seq] = true
	}
	for headSeq > 0 {
		page, err := d.Query(ctx, Filter{AfterSeq: after, MaxSeq: headSeq, Limit: 5000})
		if err != nil {
			return total, err
		}
		if len(page) == 0 {
			break
		}
		if page[0].Seq != after+1 {
			total.problem("seq gap: %d follows %d", page[0].Seq, after)
		}
		r := VerifyEntries(page, prev)
		if total.FirstSeq == 0 {
			total.FirstSeq = r.FirstSeq
		}
		total.Checked += r.Checked
		total.LastSeq, total.LastHash = r.LastSeq, r.LastHash
		for _, p := range r.Problems {
			total.problem("%s", p)
		}
		for _, e := range page {
			if want[e.Seq] {
				hashAt[e.Seq] = e.Hash
			}
			if e.EventType == EventRootSealed {
				var b struct {
					Data map[string]any `json:"data"`
				}
				if json.Unmarshal([]byte(e.BodyJSON), &b) == nil {
					if day, ok := b.Data["day"].(string); ok {
						sealedEvents[day] = b.Data
					}
				}
			}
		}
		prev = r.LastHash
		after = r.LastSeq
		if after >= headSeq {
			break
		}
	}
	if headSeq != total.LastSeq || (headSeq > 0 && headHash != total.LastHash) {
		total.problem("head (seq %d, %s) does not match last entry (seq %d, %s): entries missing or altered", headSeq, short(headHash), total.LastSeq, short(total.LastHash))
	}
	seenDays := map[string]bool{}
	for _, r := range roots {
		day := strings.TrimPrefix(r.Scope, "day:")
		seenDays[day] = true
		if ev, ok := sealedEvents[day]; !ok {
			if r.Seq < headSeq {
				total.problem("sealed root %s has no diary.root_sealed event in the chain", r.Scope)
			}
		} else if fmt.Sprint(ev["root_hash"]) != r.RootHash || fmt.Sprint(ev["signature"]) != r.Signature {
			total.problem("sealed root %s differs from the root recorded in the chain", r.Scope)
		}
		got, ok := hashAt[r.Seq]
		switch {
		case r.Seq > headSeq:
			total.problem("sealed root %s covers seq %d beyond the chain end %d: entries were removed", r.Scope, r.Seq, headSeq)
		case !ok:
			total.problem("sealed root %s: entry seq %d is missing", r.Scope, r.Seq)
		case got != r.RootHash:
			total.problem("sealed root %s: entry seq %d hash %s != sealed root %s: chain rewritten", r.Scope, r.Seq, short(got), short(r.RootHash))
		}
		if !d.rootTrusted(&r) {
			total.problem("sealed root %s: signature does not verify against a trusted key (%s)", r.Scope, r.KeyID)
		}
	}
	// A diary.root_sealed event whose diary_roots row was deleted.
	for day := range sealedEvents {
		if !seenDays[day] {
			total.problem("diary records a sealed root for %s but the diary_roots row is missing", day)
		}
	}
	if len(roots) > 0 && len(d.trusted) == 0 {
		total.Warnings = append(total.Warnings, "no trusted root key pinned: sealed roots are only checked against their embedded key")
	}
	return total, nil
}

// rootTrusted verifies a sealed root against the pinned keys. A root with no
// stored public key (sealed before migration 0002) is matched by key_id.
func (d *Diary) rootTrusted(r *SignedRoot) bool {
	if len(d.trusted) == 0 {
		return r.PublicKey != "" && VerifyRoot(*r)
	}
	for _, k := range d.trusted {
		enc := base64.StdEncoding.EncodeToString(k)
		sum := sha256.Sum256(k)
		kid := "ed25519:" + hex.EncodeToString(sum[:8])
		if r.PublicKey == enc || (r.PublicKey == "" && r.KeyID == kid) {
			c := *r
			c.PublicKey = enc
			if VerifyRoot(c) {
				return true
			}
		}
	}
	return false
}

// roots loads sealed daily roots up to maxSeq as SignedRoots.
func (d *Diary) roots(ctx context.Context) ([]SignedRoot, error) {
	rows, err := d.pool.Query(ctx, `SELECT day, last_seq, root_hash, signature, key_id, public_key, sealed_at
		FROM diary_roots ORDER BY day`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SignedRoot
	for rows.Next() {
		var day, at time.Time
		var r SignedRoot
		if err := rows.Scan(&day, &r.Seq, &r.RootHash, &r.Signature, &r.KeyID, &r.PublicKey, &at); err != nil {
			return nil, err
		}
		r.Scope = "day:" + day.Format(time.DateOnly)
		r.SignedAt = at.UTC().Format(time.RFC3339Nano)
		r.Message = rootMessage(r.Scope, r.Seq, r.RootHash, r.SignedAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Signer signs root hashes with Ed25519.
type Signer struct {
	key   ed25519.PrivateKey
	KeyID string
}

// NewSigner parses a base64 Ed25519 seed (32 bytes) or full private key (64 bytes).
func NewSigner(b64 []byte) (*Signer, error) {
	raw, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		return nil, fmt.Errorf("diary signing key: not base64: %w", err)
	}
	var key ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize:
		key = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		key = ed25519.PrivateKey(raw)
	default:
		return nil, errors.New("diary signing key: want 32-byte seed or 64-byte private key")
	}
	pub := key.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return &Signer{key: key, KeyID: "ed25519:" + hex.EncodeToString(sum[:8])}, nil
}

func (s *Signer) PublicKey() string {
	return base64.StdEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey))
}

// SignedRoot attests that the chain had RootHash at Seq.
type SignedRoot struct {
	Seq       int64  `json:"seq"`
	RootHash  string `json:"root_hash"`
	Scope     string `json:"scope"` // "head" or "day:YYYY-MM-DD"
	SignedAt  string `json:"signed_at"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Message   string `json:"message"`   // exact bytes signed
	Signature string `json:"signature"` // base64
}

func rootMessage(scope string, seq int64, hash, signedAt string) string {
	return fmt.Sprintf("fortik-diary-root/v1\nscope=%s\nseq=%d\nroot=%s\nsigned_at=%s", scope, seq, hash, signedAt)
}

func (s *Signer) Sign(scope string, seq int64, hash string, at time.Time) SignedRoot {
	signedAt := at.UTC().Format(time.RFC3339Nano)
	msg := rootMessage(scope, seq, hash, signedAt)
	return SignedRoot{Seq: seq, RootHash: hash, Scope: scope, SignedAt: signedAt, KeyID: s.KeyID,
		PublicKey: s.PublicKey(), Message: msg,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, []byte(msg)))}
}

// VerifyRoot checks a SignedRoot's signature against its embedded public key
// (callers must also pin the expected key id / public key out of band).
func VerifyRoot(r SignedRoot) bool {
	pub, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return false
	}
	if r.Message != rootMessage(r.Scope, r.Seq, r.RootHash, r.SignedAt) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(r.Message), sig)
}

// Export is the GET /v1/diary/export document.
type Export struct {
	ExportedAt   string      `json:"exported_at"`
	Filter       any         `json:"filter"`
	Contiguous   bool        `json:"contiguous"` // false when filtered by agent: continuity cannot be proven, each entry still self-verifies
	Entries      []Entry     `json:"entries"`
	Verification Report      `json:"verification"`
	ChainCheck   Report      `json:"chain_check"` // full-chain verification at export time
	Signed       bool        `json:"signed"`      // false when the chain failed verification: Fortik never signs a broken chain
	SegmentRoot  *SignedRoot `json:"segment_root,omitempty"`
	HeadRoot     *SignedRoot `json:"head_root,omitempty"`
	Warning      string      `json:"warning,omitempty"`
	Algorithm    string      `json:"algorithm"`
}

// Export builds a verifiable export. For a contiguous export the segment root
// signs the last exported entry, so an offline verifier can check the
// entries alone; the head root signs the chain head at export time. Nothing
// is signed if full-chain verification fails.
func (d *Diary) Export(ctx context.Context, f Filter, s *Signer, actor string) (Export, error) {
	if s == nil {
		return Export{}, errors.New("diary export: no signing key configured")
	}
	if f.Limit <= 0 || f.Limit > 10000 {
		f.Limit = 10000
	}
	chain, err := d.VerifyChain(ctx)
	if err != nil {
		return Export{}, err
	}
	f.MaxSeq = chain.HeadSeq // export exactly what was verified
	entries, err := d.Query(ctx, f)
	if err != nil {
		return Export{}, err
	}
	var seg Report
	// Any filter that selects entries by content (agent, action) yields a
	// non-contiguous subset: each entry is verified on its own and no segment
	// root is signed (the head root still covers the whole chain).
	contiguous := f.AgentID == "" && f.ActionID == ""
	if contiguous {
		seg = VerifyEntries(entries, "")
		if len(entries) > 0 && entries[0].Seq == 1 && entries[0].PrevHash != GenesisHash {
			seg.problem("first entry does not link to genesis")
		}
	} else {
		seg = Report{OK: true}
		for _, e := range entries {
			if ComputeHash(e.PrevHash, e.BodyJSON) != e.Hash {
				seg.problem("seq %d: hash mismatch", e.Seq)
			}
			seg.Checked++
		}
	}
	now := time.Now().UTC()
	exp := Export{
		ExportedAt: now.Format(time.RFC3339Nano),
		Filter: map[string]any{"agent_id": f.AgentID, "action_id": f.ActionID, "from": f.From, "to": f.To, "after_seq": f.AfterSeq,
			"max_seq": f.MaxSeq, "limit": f.Limit},
		Contiguous: contiguous, Entries: entries, Verification: seg, ChainCheck: chain,
		Algorithm: "hash = sha256(prev_hash_hex || body_json); genesis prev_hash = 64 x '0'; roots: Ed25519 over 'message'",
	}
	if chain.OK && seg.OK {
		exp.Signed = true
		head := s.Sign("head", chain.HeadSeq, chain.HeadHash, now)
		exp.HeadRoot = &head
		if contiguous && len(entries) > 0 {
			first, last := entries[0], entries[len(entries)-1]
			sr := s.Sign(fmt.Sprintf("export:%d-%d", first.Seq, last.Seq), last.Seq, last.Hash, now)
			exp.SegmentRoot = &sr
		}
	} else {
		exp.Warning = "chain verification FAILED: export is unsigned; see chain_check.problems"
	}
	if _, err := d.Append(ctx, Event{EventType: EventExported, Actor: actor, AgentID: f.AgentID, Data: map[string]any{
		"entries": len(entries), "head_seq": chain.HeadSeq, "head_hash": chain.HeadHash, "chain_ok": chain.OK, "signed": exp.Signed,
	}}); err != nil {
		return Export{}, err
	}
	return exp, nil
}

// SealDay records the signed root for a UTC day (the hash of the last entry
// with ts before the end of that day). Idempotent per day.
func (d *Diary) SealDay(ctx context.Context, day time.Time, s *Signer, actor string) (SignedRoot, error) {
	if s == nil {
		return SignedRoot{}, errors.New("diary seal: no signing key configured")
	}
	day = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
	end := day.Add(24 * time.Hour)
	if !time.Now().UTC().After(end) {
		return SignedRoot{}, fmt.Errorf("diary seal: day %s has not ended", day.Format(time.DateOnly))
	}
	if chain, err := d.VerifyChain(ctx); err != nil {
		return SignedRoot{}, err
	} else if !chain.OK {
		return SignedRoot{}, fmt.Errorf("diary seal: refusing to sign a chain that fails verification: %v", chain.Problems)
	}
	var out SignedRoot
	err := pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		// Serialise with appends so no entry for the day can land mid-seal.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM diary_head WHERE id FOR UPDATE`); err != nil {
			return err
		}
		var existing struct {
			seq           int64
			hash          string
			sig, kid, pub string
			at            time.Time
		}
		err := tx.QueryRow(ctx, `SELECT last_seq, root_hash, signature, key_id, public_key, sealed_at FROM diary_roots WHERE day = $1`, day).
			Scan(&existing.seq, &existing.hash, &existing.sig, &existing.kid, &existing.pub, &existing.at)
		if err == nil {
			scope := "day:" + day.Format(time.DateOnly)
			signedAt := existing.at.UTC().Format(time.RFC3339Nano)
			out = SignedRoot{Seq: existing.seq, RootHash: existing.hash, Scope: scope, SignedAt: signedAt,
				KeyID: existing.kid, PublicKey: existing.pub, Message: rootMessage(scope, existing.seq, existing.hash, signedAt), Signature: existing.sig}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var seq int64
		var hash string
		err = tx.QueryRow(ctx, `SELECT seq, hash FROM diary WHERE ts < $1 ORDER BY seq DESC LIMIT 1`, end).Scan(&seq, &hash)
		if errors.Is(err, pgx.ErrNoRows) {
			seq, hash = 0, GenesisHash
		} else if err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		out = s.Sign("day:"+day.Format(time.DateOnly), seq, hash, now)
		if _, err := tx.Exec(ctx, `INSERT INTO diary_roots (day, last_seq, root_hash, signature, key_id, public_key, sealed_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			day, seq, hash, out.Signature, out.KeyID, out.PublicKey, now); err != nil {
			return err
		}
		_, err = d.AppendTx(ctx, tx, Event{EventType: EventRootSealed, Actor: actor, Data: map[string]any{
			"day": day.Format(time.DateOnly), "last_seq": seq, "root_hash": hash, "key_id": out.KeyID, "signature": out.Signature,
		}})
		return err
	})
	return out, err
}

package swarm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/diary"
)

// Bundle is GET /v1/swarms/{id}/bundle: the sealed kill-swarm record and
// every Diary event about the swarm, verified and signed like a Diary
// export. Nothing is signed if the chain fails verification.
type Bundle struct {
	SwarmID      string            `json:"swarm_id"`
	ExportedAt   string            `json:"exported_at"`
	Sealed       diary.Entry       `json:"sealed"`  // the latest swarm.sealed entry
	Entries      []diary.Entry     `json:"entries"` // every entry whose data.swarm_id is this swarm, seq order
	Truncated    bool              `json:"truncated,omitempty"`
	Verification diary.Report      `json:"verification"` // each entry's hash recomputed
	ChainCheck   diary.Report      `json:"chain_check"`  // full-chain verification at export time
	Signed       bool              `json:"signed"`
	BundleRoot   *diary.SignedRoot `json:"bundle_root,omitempty"` // signs the sealed entry's hash (scope swarm-bundle:<id>)
	HeadRoot     *diary.SignedRoot `json:"head_root,omitempty"`
	Warning      string            `json:"warning,omitempty"`
	Algorithm    string            `json:"algorithm"`
	Swarm        Swarm             `json:"swarm"`
}

const maxBundleEntries = 10000

const entryCols = `seq, ts, COALESCE(agent_id, ''), event_type, actor, body_json, prev_hash, hash`

func scanEntries(rows pgx.Rows) ([]diary.Entry, error) {
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (diary.Entry, error) {
		var e diary.Entry
		err := r.Scan(&e.Seq, &e.TS, &e.AgentID, &e.EventType, &e.Actor, &e.BodyJSON, &e.PrevHash, &e.Hash)
		e.Body = json.RawMessage(e.BodyJSON)
		e.TS = e.TS.UTC()
		return e, err
	})
}

// Bundle builds the signed export of the swarm's sealed bundle (the swarm
// must have been killed: step 7 seals it) and records swarm.bundle_exported.
func (s *Service) Bundle(ctx context.Context, id, actor string) (Bundle, error) {
	if err := checkID(id); err != nil {
		return Bundle{}, err
	}
	if s.opt.Signer == nil {
		return Bundle{}, ErrNoSigner
	}
	sw, err := getSwarm(ctx, s.pool, id, false)
	if err != nil {
		return Bundle{}, err
	}
	chain, err := s.diary.VerifyChain(ctx)
	if err != nil {
		return Bundle{}, err
	}
	since := sw.CreatedAt.Add(-time.Minute)
	rows, err := s.pool.Query(ctx, `SELECT `+entryCols+` FROM diary
		WHERE event_type = $1 AND ts >= $2 AND seq <= $3 AND body_json::jsonb #>> '{data,swarm_id}' = $4
		ORDER BY seq DESC LIMIT 1`, EventSealed, since, chain.HeadSeq, id)
	if err != nil {
		return Bundle{}, err
	}
	sealed, err := scanEntries(rows)
	if err != nil {
		return Bundle{}, err
	}
	if len(sealed) == 0 {
		return Bundle{}, ErrNotSealed
	}
	rows, err = s.pool.Query(ctx, `SELECT `+entryCols+` FROM diary
		WHERE ts >= $1 AND seq <= $2 AND body_json::jsonb #>> '{data,swarm_id}' = $3
		ORDER BY seq LIMIT $4`, since, chain.HeadSeq, id, maxBundleEntries+1)
	if err != nil {
		return Bundle{}, err
	}
	entries, err := scanEntries(rows)
	if err != nil {
		return Bundle{}, err
	}
	b := Bundle{SwarmID: id, Sealed: sealed[0], Entries: entries, ChainCheck: chain, Swarm: sw,
		Algorithm: "hash = sha256(prev_hash_hex || body_json); genesis prev_hash = 64 x '0'; roots: Ed25519 over 'message'; " +
			"entries are not contiguous: each entry self-verifies and links into the chain verified in chain_check"}
	if len(b.Entries) > maxBundleEntries {
		b.Entries, b.Truncated = b.Entries[:maxBundleEntries], true
	}
	b.Verification = diary.Report{OK: true}
	for _, e := range append([]diary.Entry{b.Sealed}, b.Entries...) {
		b.Verification.Checked++
		if diary.ComputeHash(e.PrevHash, e.BodyJSON) != e.Hash {
			b.Verification.OK = false
			b.Verification.Problems = append(b.Verification.Problems, fmt.Sprintf("seq %d: hash mismatch", e.Seq))
		}
	}
	now := time.Now().UTC()
	b.ExportedAt = now.Format(time.RFC3339Nano)
	if chain.OK && b.Verification.OK {
		b.Signed = true
		head := s.opt.Signer.Sign("head", chain.HeadSeq, chain.HeadHash, now)
		root := s.opt.Signer.Sign("swarm-bundle:"+id, b.Sealed.Seq, b.Sealed.Hash, now)
		b.HeadRoot, b.BundleRoot = &head, &root
	} else {
		b.Warning = "chain verification FAILED: bundle is unsigned; see chain_check and verification problems"
	}
	if _, err := s.diary.Append(ctx, diary.Event{EventType: EventBundleExported, Actor: actor, Data: map[string]any{
		"swarm_id": id, "sealed_seq": b.Sealed.Seq, "sealed_hash": b.Sealed.Hash, "entries": len(b.Entries),
		"head_seq": chain.HeadSeq, "chain_ok": chain.OK, "signed": b.Signed,
	}}); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

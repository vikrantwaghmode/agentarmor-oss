package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// VerificationReport summarizes an integrity check of an audit log directory.
// OK is true only when the hash chain, every Merkle seal, and every signature
// all verify. Problems lists every anomaly found (verification does not stop at
// the first error, so an auditor sees the full picture).
type VerificationReport struct {
	OK            bool     `json:"ok"`
	Records       int      `json:"records"`
	Seals         int      `json:"seals"`
	SealedRecords int      `json:"sealed_records"`
	Problems      []string `json:"problems,omitempty"`
}

func (r *VerificationReport) fail(format string, args ...interface{}) {
	r.OK = false
	r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
}

// Verify replays the on-disk log and seals in dir and checks every integrity
// invariant against the given signer. It is a pure read — safe to run on a copy
// of the logs handed to an external auditor (with the public key / shared HMAC
// verification key).
func Verify(dir string, signer SealSigner) (*VerificationReport, error) {
	rep := &VerificationReport{OK: true}

	// ── 1. Replay the record hash chain ──
	records, err := readRecords(filepath.Join(dir, "audit.log"))
	if err != nil {
		return nil, err
	}
	rep.Records = len(records)
	leafBySeq := make(map[uint64]Hash, len(records))
	prev := Hash{}
	var expectedSeq uint64 = 1
	for _, rec := range records {
		if rec.Seq != expectedSeq {
			rep.fail("sequence gap: expected seq %d, found %d (record deleted or reordered)", expectedSeq, rec.Seq)
		}
		expectedSeq = rec.Seq + 1

		body, err := CanonicalBytes(rec.Event)
		if err != nil {
			rep.fail("seq %d: cannot canonicalize event: %v", rec.Seq, err)
			prev = mustHex(rec.RecHash, prev)
			continue
		}
		leaf := LeafHash(body)
		if HexHash(leaf) != rec.LeafHash {
			rep.fail("seq %d: leaf hash mismatch — event body was altered", rec.Seq)
		}
		if rec.PrevHash != HexHash(prev) {
			rep.fail("seq %d: prev_hash mismatch — a prior record was altered/removed", rec.Seq)
		}
		recHash := NodeHash(prev, leaf)
		if HexHash(recHash) != rec.RecHash {
			rep.fail("seq %d: rec_hash mismatch — chain link broken", rec.Seq)
		}
		leafBySeq[rec.Seq] = leaf
		prev = recHash
	}

	// ── 2. Verify every Merkle seal + signature + seal-of-seals chain ──
	quotes, err := readQuotes(filepath.Join(dir, "seals.log"))
	if err != nil {
		return nil, err
	}
	rep.Seals = len(quotes)
	prevRoot := Hash{}
	for _, q := range quotes {
		if !q.VerifySignature(signer) {
			rep.fail("seal %d: signature verification failed", q.SealID)
		}
		if q.PrevRoot != hexOrEmpty(prevRoot) {
			rep.fail("seal %d: prev_root mismatch — a previous seal was altered/removed", q.SealID)
		}
		// Rebuild the Merkle root from the records this seal covers.
		var leaves []Hash
		missing := false
		for s := q.SeqStart; s <= q.SeqEnd; s++ {
			leaf, ok := leafBySeq[s]
			if !ok {
				rep.fail("seal %d: missing record seq %d covered by this seal", q.SealID, s)
				missing = true
				break
			}
			leaves = append(leaves, leaf)
		}
		if !missing {
			root := MerkleRoot(leaves)
			if HexHash(root) != q.MerkleRoot {
				rep.fail("seal %d: Merkle root mismatch — sealed events were tampered with", q.SealID)
			}
			rep.SealedRecords += len(leaves)
			if parsed, err := ParseHexHash(q.MerkleRoot); err == nil {
				prevRoot = parsed
			}
		}
	}
	return rep, nil
}

// ReadRecords loads every sealed record from dir/audit.log, in order. Exposed
// for the Phase 4 compliance reporter (read-only consumption of the log).
func ReadRecords(dir string) ([]SealedRecord, error) {
	return readRecords(filepath.Join(dir, "audit.log"))
}

// ReadSeals loads every attestation quote from dir/seals.log, in order.
func ReadSeals(dir string) ([]AttestationQuote, error) {
	return readQuotes(filepath.Join(dir, "seals.log"))
}

func readRecords(path string) ([]SealedRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []SealedRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var rec SealedRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, fmt.Errorf("audit: corrupt record line: %w", err)
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

func readQuotes(path string) ([]AttestationQuote, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []AttestationQuote
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var q AttestationQuote
		if err := json.Unmarshal(sc.Bytes(), &q); err != nil {
			return nil, fmt.Errorf("audit: corrupt seal line: %w", err)
		}
		out = append(out, q)
	}
	return out, sc.Err()
}

// mustHex parses a hex hash, falling back to a default when parsing fails (used
// only to keep the chain walk progressing after an already-reported error).
func mustHex(s string, fallback Hash) Hash {
	if h, err := ParseHexHash(s); err == nil {
		return h
	}
	return fallback
}

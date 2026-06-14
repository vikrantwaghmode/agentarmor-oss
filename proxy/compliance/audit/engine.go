package audit

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SealedRecord is one line of the append-only audit log. It wraps the hashed
// event body with integrity metadata: a monotonic sequence number, the leaf
// hash of the body, and PrevHash — a hash chain over (prevHash || leafHash)
// that makes deletion or reordering of any record detectable even between
// Merkle seals.
type SealedRecord struct {
	Seq      uint64     `json:"seq"`
	Event    AuditEvent `json:"event"`
	LeafHash string     `json:"leaf_hash"` // hex BLAKE3 leaf hash of the canonical body
	PrevHash string     `json:"prev_hash"` // hex hash-chain link to the previous record
	RecHash  string     `json:"rec_hash"`  // hex chain hash = H(prev || leaf), this record's link
}

// Engine is the cryptographic audit log. Append is safe for concurrent use.
//
// Layout under Dir:
//
//	audit.log    — JSONL, one SealedRecord per line (append-only)
//	seals.log    — JSONL, one AttestationQuote per Seal() (append-only)
type Engine struct {
	mu        sync.Mutex
	dir       string
	logPath   string
	sealPath  string
	logFile   *os.File
	signer    SealSigner
	seq       uint64 // last assigned sequence
	prevHash  Hash   // running chain hash (rec_hash of last record)
	sealID    uint64 // last seal id
	prevRoot  Hash   // last seal's Merkle root (seal-of-seals chain)
	pending   []Hash // leaf hashes since last seal, in order
	pendStart uint64 // seq of first pending leaf
}

// New opens (or creates) an audit log in dir and replays any existing records
// to restore the chain state, so a restarted process keeps appending to the
// same tamper-evident chain rather than forking it.
func New(dir string, signer SealSigner) (*Engine, error) {
	if signer == nil {
		return nil, fmt.Errorf("audit: signer is required")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("audit: mkdir %s: %w", dir, err)
	}
	e := &Engine{
		dir:      dir,
		logPath:  filepath.Join(dir, "audit.log"),
		sealPath: filepath.Join(dir, "seals.log"),
		signer:   signer,
	}
	if err := e.replay(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(e.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit: open log: %w", err)
	}
	e.logFile = f
	return e, nil
}

// replay restores seq/prevHash/sealID/prevRoot/pending from disk.
func (e *Engine) replay() error {
	// Restore seal state first (sealID, prevRoot, and the last sealed seq).
	var lastSealedSeq uint64
	if sf, err := os.Open(e.sealPath); err == nil {
		sc := bufio.NewScanner(sf)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			var q AttestationQuote
			if err := json.Unmarshal(line, &q); err != nil {
				sf.Close()
				return fmt.Errorf("audit: corrupt seal line: %w", err)
			}
			e.sealID = q.SealID
			lastSealedSeq = q.SeqEnd
			if root, err := ParseHexHash(q.MerkleRoot); err == nil {
				e.prevRoot = root
			}
		}
		sf.Close()
	}

	// Restore record chain and rebuild the pending (unsealed) leaf set.
	lf, err := os.Open(e.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // fresh log
		}
		return fmt.Errorf("audit: open log for replay: %w", err)
	}
	defer lf.Close()
	sc := bufio.NewScanner(lf)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec SealedRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("audit: corrupt log line: %w", err)
		}
		leaf, err := ParseHexHash(rec.LeafHash)
		if err != nil {
			return fmt.Errorf("audit: bad leaf hash at seq %d: %w", rec.Seq, err)
		}
		recHash, err := ParseHexHash(rec.RecHash)
		if err != nil {
			return fmt.Errorf("audit: bad rec hash at seq %d: %w", rec.Seq, err)
		}
		e.seq = rec.Seq
		e.prevHash = recHash
		if rec.Seq > lastSealedSeq {
			if len(e.pending) == 0 {
				e.pendStart = rec.Seq
			}
			e.pending = append(e.pending, leaf)
		}
	}
	return sc.Err()
}

// Append serializes, hashes, hash-chains, and durably writes an event. It fills
// in EventID/SchemaVersion/Timestamp if the caller left them blank and returns
// the persisted record. Cheap enough to call inline on the request path.
func (e *Engine) Append(ev AuditEvent) (SealedRecord, error) {
	if ev.SchemaVersion == "" {
		ev.SchemaVersion = SchemaVersion
	}
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if ev.EventID == "" {
		ev.EventID = randID()
	}
	body, err := CanonicalBytes(ev)
	if err != nil {
		return SealedRecord{}, fmt.Errorf("audit: canonicalize: %w", err)
	}
	leaf := LeafHash(body)

	e.mu.Lock()
	defer e.mu.Unlock()

	e.seq++
	recHash := NodeHash(e.prevHash, leaf) // chain link: H(prev || leaf)
	rec := SealedRecord{
		Seq:      e.seq,
		Event:    ev,
		LeafHash: HexHash(leaf),
		PrevHash: HexHash(e.prevHash),
		RecHash:  HexHash(recHash),
	}
	line, err := json.Marshal(rec)
	if err != nil {
		e.seq--
		return SealedRecord{}, fmt.Errorf("audit: marshal record: %w", err)
	}
	if _, err := e.logFile.Write(append(line, '\n')); err != nil {
		e.seq--
		return SealedRecord{}, fmt.Errorf("audit: write record: %w", err)
	}
	// Best-effort durability; callers needing strict fsync-per-event can wrap.
	_ = e.logFile.Sync()

	e.prevHash = recHash
	if len(e.pending) == 0 {
		e.pendStart = e.seq
	}
	e.pending = append(e.pending, leaf)
	return rec, nil
}

// Seal computes a Merkle root over all events appended since the last seal,
// signs it into an attestation quote, and durably appends the quote. Returns
// (nil, nil) when there is nothing new to seal. Call periodically (timer) and
// on shutdown.
func (e *Engine) Seal() (*AttestationQuote, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.pending) == 0 {
		return nil, nil
	}
	root := MerkleRoot(e.pending)
	e.sealID++
	q := AttestationQuote{
		Type:       "agentarmor.audit.seal",
		SealID:     e.sealID,
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		SeqStart:   e.pendStart,
		SeqEnd:     e.seq,
		EventCount: len(e.pending),
		HashAlgo:   HashAlgo,
		MerkleRoot: HexHash(root),
		PrevRoot:   hexOrEmpty(e.prevRoot),
	}
	q.sign(e.signer)

	line, err := json.Marshal(q)
	if err != nil {
		e.sealID--
		return nil, fmt.Errorf("audit: marshal seal: %w", err)
	}
	sf, err := os.OpenFile(e.sealPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		e.sealID--
		return nil, fmt.Errorf("audit: open seals: %w", err)
	}
	if _, err := sf.Write(append(line, '\n')); err != nil {
		sf.Close()
		e.sealID--
		return nil, fmt.Errorf("audit: write seal: %w", err)
	}
	_ = sf.Sync()
	sf.Close()

	e.prevRoot = root
	e.pending = nil
	e.pendStart = 0
	return &q, nil
}

// Close seals any remaining events and closes the log file.
func (e *Engine) Close() error {
	if _, err := e.Seal(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.logFile != nil {
		return e.logFile.Close()
	}
	return nil
}

func hexOrEmpty(h Hash) string {
	if h == (Hash{}) {
		return ""
	}
	return HexHash(h)
}

func randID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

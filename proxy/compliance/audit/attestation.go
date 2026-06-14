package audit

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// SealSigner binds a Merkle root (and its metadata) into a signature, providing
// non-repudiation. Two adapters are provided: HMAC-SHA256 (shared-secret, the
// default — simplest to operate) and Ed25519 (asymmetric, for third-party
// verifiability without sharing the signing key).
type SealSigner interface {
	// Sign returns a signature over digest plus the algorithm and key id.
	Sign(digest []byte) (sig []byte, algo string, keyID string)
	// Verify checks a signature previously produced by a compatible signer.
	Verify(digest, sig []byte) bool
	// Algo / KeyID describe the signer for the attestation quote header.
	Algo() string
	KeyID() string
}

// ── HMAC-SHA256 adapter ─────────────────────────────────────────────────────

// HMACSigner signs with HMAC-SHA256 over a shared secret. keyID is a non-secret
// label (e.g. a key version) recorded in the quote so keys can be rotated.
type HMACSigner struct {
	key   []byte
	keyID string
}

// NewHMACSigner builds an HMAC-SHA256 signer. The key must be kept secret and
// ideally injected from AgentArmor's secrets provider, not the policy file.
func NewHMACSigner(key []byte, keyID string) (*HMACSigner, error) {
	if len(key) < 16 {
		return nil, errors.New("audit: HMAC key must be at least 16 bytes")
	}
	return &HMACSigner{key: key, keyID: keyID}, nil
}

func (s *HMACSigner) Sign(digest []byte) ([]byte, string, string) {
	m := hmac.New(sha256.New, s.key)
	m.Write(digest)
	return m.Sum(nil), s.Algo(), s.keyID
}

func (s *HMACSigner) Verify(digest, sig []byte) bool {
	m := hmac.New(sha256.New, s.key)
	m.Write(digest)
	return hmac.Equal(m.Sum(nil), sig) // constant-time
}

func (s *HMACSigner) Algo() string  { return "HMAC-SHA256" }
func (s *HMACSigner) KeyID() string { return s.keyID }

// ── Ed25519 adapter (optional, asymmetric) ──────────────────────────────────

// Ed25519Signer signs with an Ed25519 private key; auditors verify with the
// public key alone, so the signing key never leaves AgentArmor.
type Ed25519Signer struct {
	priv  ed25519.PrivateKey
	keyID string
}

// NewEd25519Signer wraps an Ed25519 private key.
func NewEd25519Signer(priv ed25519.PrivateKey, keyID string) (*Ed25519Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("audit: invalid Ed25519 private key size")
	}
	return &Ed25519Signer{priv: priv, keyID: keyID}, nil
}

func (s *Ed25519Signer) Sign(digest []byte) ([]byte, string, string) {
	return ed25519.Sign(s.priv, digest), s.Algo(), s.keyID
}

func (s *Ed25519Signer) Verify(digest, sig []byte) bool {
	return ed25519.Verify(s.priv.Public().(ed25519.PublicKey), digest, sig)
}

func (s *Ed25519Signer) Algo() string  { return "Ed25519" }
func (s *Ed25519Signer) KeyID() string { return s.keyID }

// ── Attestation quote ───────────────────────────────────────────────────────

// AttestationQuote is the signed seal over a contiguous batch of events. It is
// the unit auditors verify: it binds a Merkle root to the batch range, the hash
// and signature algorithms, and a signature for non-repudiation.
type AttestationQuote struct {
	Type       string `json:"type"`        // "agentarmor.audit.seal"
	SealID     uint64 `json:"seal_id"`     // monotonically increasing
	Timestamp  string `json:"@timestamp"`  // RFC3339Nano UTC
	SeqStart   uint64 `json:"seq_start"`   // first event sequence in this batch
	SeqEnd     uint64 `json:"seq_end"`     // last event sequence (inclusive)
	EventCount int    `json:"event_count"` // SeqEnd-SeqStart+1
	HashAlgo   string `json:"hash_algo"`   // e.g. BLAKE3-256
	MerkleRoot string `json:"merkle_root"` // hex
	PrevRoot   string `json:"prev_root"`   // hex of previous seal's root (seal-of-seals chain), empty for first
	SigAlgo    string `json:"sig_algo"`    // HMAC-SHA256 | Ed25519
	KeyID      string `json:"key_id"`      // non-secret key label
	Signature  string `json:"signature"`   // hex signature over the signing digest
}

// signingDigest is the exact byte string signed/verified for a quote. It binds
// every security-relevant field so none can be altered without detection. The
// signature field itself is excluded (it's the output).
func (q AttestationQuote) signingDigest() []byte {
	h := hashWith(0x02,
		[]byte(q.Type),
		[]byte(itoa(q.SealID)),
		[]byte(q.Timestamp),
		[]byte(itoa(q.SeqStart)),
		[]byte(itoa(q.SeqEnd)),
		[]byte(q.HashAlgo),
		[]byte(q.MerkleRoot),
		[]byte(q.PrevRoot),
		[]byte(q.SigAlgo),
		[]byte(q.KeyID),
	)
	return h[:]
}

// sign populates SigAlgo/KeyID/Signature on the quote. SigAlgo/KeyID are set
// *before* computing the digest because signingDigest() binds them, so signing
// and verification hash the identical field set.
func (q *AttestationQuote) sign(signer SealSigner) {
	q.SigAlgo = signer.Algo()
	q.KeyID = signer.KeyID()
	sig, _, _ := signer.Sign(q.signingDigest())
	q.Signature = hex.EncodeToString(sig)
}

// VerifySignature checks the quote's signature with the given signer.
func (q AttestationQuote) VerifySignature(signer SealSigner) bool {
	sig, err := hex.DecodeString(q.Signature)
	if err != nil {
		return false
	}
	return signer.Verify(q.signingDigest(), sig)
}

// itoa avoids importing strconv just for unsigned ints in the digest.
func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

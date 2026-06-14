package audit

import (
	"encoding/hex"
	"errors"
)

// MerkleRoot reduces leaf digests into a single root (the "reduce" half of the
// map-reduce). An odd node at any level is promoted by duplicating it
// (Bitcoin/RFC-6962-style), so the tree is always full. Returns the zero hash
// for an empty input, which callers treat as "nothing to seal".
func MerkleRoot(leaves []Hash) Hash {
	if len(leaves) == 0 {
		return Hash{}
	}
	level := make([]Hash, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([]Hash, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, NodeHash(level[i], level[i+1]))
		}
		level = next
	}
	return level[0]
}

// ProofStep is one sibling on the path from a leaf to the root.
type ProofStep struct {
	Hash    Hash `json:"hash"`
	IsRight bool `json:"is_right"` // true if the sibling sits to the right of the running hash
}

// InclusionProof returns the audit path proving that leaf at index is part of
// the tree over leaves. The proof + leaf + root is independently verifiable by
// an auditor who never sees the other events.
func InclusionProof(leaves []Hash, index int) ([]ProofStep, error) {
	if index < 0 || index >= len(leaves) {
		return nil, errors.New("audit: leaf index out of range")
	}
	level := make([]Hash, len(leaves))
	copy(level, leaves)
	idx := index
	var proof []ProofStep
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		if idx%2 == 0 {
			proof = append(proof, ProofStep{Hash: level[idx+1], IsRight: true})
		} else {
			proof = append(proof, ProofStep{Hash: level[idx-1], IsRight: false})
		}
		next := make([]Hash, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, NodeHash(level[i], level[i+1]))
		}
		level = next
		idx /= 2
	}
	return proof, nil
}

// VerifyProof recomputes the root from a leaf and its audit path and reports
// whether it equals the expected root.
func VerifyProof(leaf Hash, proof []ProofStep, root Hash) bool {
	cur := leaf
	for _, step := range proof {
		if step.IsRight {
			cur = NodeHash(cur, step.Hash)
		} else {
			cur = NodeHash(step.Hash, cur)
		}
	}
	return cur == root
}

// HexHash renders a digest as lowercase hex (used in JSON quotes / reports).
func HexHash(h Hash) string { return hex.EncodeToString(h[:]) }

// ParseHexHash parses a lowercase-hex digest back into a Hash.
func ParseHexHash(s string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, err
	}
	if len(b) != HashSize {
		return h, errors.New("audit: bad hash length")
	}
	copy(h[:], b)
	return h, nil
}

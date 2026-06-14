package audit

import (
	"encoding/json"
	"runtime"
	"sync"

	"lukechampine.com/blake3"
)

// HashAlgo is recorded in every attestation quote so a verifier always uses the
// same primitive that produced the log, even if the default changes later.
const HashAlgo = "BLAKE3-256"

// HashSize is the digest length in bytes (256-bit).
const HashSize = 32

// Hash is a fixed-size BLAKE3-256 digest.
type Hash [HashSize]byte

// Domain-separation prefixes prevent a leaf from ever being reinterpreted as an
// interior node (second-preimage protection for the Merkle tree), per RFC 6962.
const (
	leafPrefix byte = 0x00
	nodePrefix byte = 0x01
)

// hashWith computes BLAKE3-256 over prefix||parts. BLAKE3 itself uses a
// tree-based compression internally, giving us parallel hashing of large
// payloads for free; we add explicit map-reduce across *events* in HashLeaves.
func hashWith(prefix byte, parts ...[]byte) Hash {
	h := blake3.New(HashSize, nil)
	h.Write([]byte{prefix})
	for _, p := range parts {
		h.Write(p)
	}
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// LeafHash hashes a canonical event body as a Merkle leaf.
func LeafHash(canonical []byte) Hash { return hashWith(leafPrefix, canonical) }

// NodeHash combines two child digests into a parent node digest.
func NodeHash(left, right Hash) Hash { return hashWith(nodePrefix, left[:], right[:]) }

// CanonicalBytes returns deterministic JSON bytes for an event body. Go's
// encoding/json emits struct fields in declaration order and sorts map keys,
// with no insignificant whitespace — so the same logical event always yields
// the same bytes (and therefore the same leaf hash) on any machine.
func CanonicalBytes(e AuditEvent) ([]byte, error) { return json.Marshal(e) }

// HashLeaves computes leaf hashes for many canonical event bodies in parallel
// (the "map" half of the map-reduce). Output is index-aligned with input. For
// small batches it runs inline to avoid goroutine overhead.
func HashLeaves(bodies [][]byte) []Hash {
	out := make([]Hash, len(bodies))
	if len(bodies) < 64 {
		for i, b := range bodies {
			out[i] = LeafHash(b)
		}
		return out
	}
	workers := runtime.GOMAXPROCS(0)
	var wg sync.WaitGroup
	ch := make(chan int, len(bodies))
	for i := range bodies {
		ch <- i
	}
	close(ch)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				out[i] = LeafHash(bodies[i])
			}
		}()
	}
	wg.Wait()
	return out
}

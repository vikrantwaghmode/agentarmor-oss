package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	dir := t.TempDir()
	signer, err := NewHMACSigner([]byte("test-hmac-key-0123456789abcdef"), "k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	e, err := New(dir, signer)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return e, dir
}

func sampleEvent(i int) AuditEvent {
	ev := NewEvent(LayerExecution, "tool_call", "ALLOWED").WithSource("203.0.113.7:5555")
	ev.AgentID = "agent-alpha"
	ev.SessionID = "sess-123"
	ev.TenantID = "default"
	ev.Tool = &Tool{Name: "exec", Parameters: map[string]interface{}{"command": "ls -la", "n": i}}
	ev.ReasoningTrace = "listing workspace to plan next step"
	ev.Output = "ok"
	ev.Labels = map[string]string{"control": "SOC2-CC7.2"}
	return ev
}

func TestAppendSealVerify(t *testing.T) {
	e, dir := newTestEngine(t)
	for i := 0; i < 10; i++ {
		if _, err := e.Append(sampleEvent(i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if _, err := e.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	for i := 10; i < 15; i++ {
		if _, err := e.Append(sampleEvent(i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := e.Close(); err != nil { // seals the remaining 5
		t.Fatalf("close: %v", err)
	}

	signer, _ := NewHMACSigner([]byte("test-hmac-key-0123456789abcdef"), "k1")
	rep, err := Verify(dir, signer)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("expected clean log, got problems: %v", rep.Problems)
	}
	if rep.Records != 15 || rep.Seals != 2 || rep.SealedRecords != 15 {
		t.Fatalf("unexpected counts: %+v", rep)
	}
}

func TestTamperBreaksVerification(t *testing.T) {
	e, dir := newTestEngine(t)
	for i := 0; i < 6; i++ {
		if _, err := e.Append(sampleEvent(i)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Tamper: flip a value inside one event body without touching its hashes.
	logPath := filepath.Join(dir, "audit.log")
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	tampered := strings.Replace(string(raw), `"output":"ok"`, `"output":"HACKED"`, 1)
	if tampered == string(raw) {
		t.Fatal("test setup: nothing replaced")
	}
	if err := os.WriteFile(logPath, []byte(tampered), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	signer, _ := NewHMACSigner([]byte("test-hmac-key-0123456789abcdef"), "k1")
	rep, err := Verify(dir, signer)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.OK {
		t.Fatal("expected verification to FAIL after tampering, but it passed")
	}
}

func TestInclusionProof(t *testing.T) {
	leaves := make([]Hash, 7)
	for i := range leaves {
		leaves[i] = LeafHash([]byte{byte(i)})
	}
	root := MerkleRoot(leaves)
	for i := range leaves {
		proof, err := InclusionProof(leaves, i)
		if err != nil {
			t.Fatalf("proof %d: %v", i, err)
		}
		if !VerifyProof(leaves[i], proof, root) {
			t.Fatalf("inclusion proof failed for leaf %d", i)
		}
	}
	// A wrong leaf must not verify against the root.
	if VerifyProof(LeafHash([]byte("nope")), nil, root) {
		t.Fatal("empty proof verified a foreign leaf")
	}
}

func TestReplayContinuesChain(t *testing.T) {
	dir := t.TempDir()
	key := []byte("test-hmac-key-0123456789abcdef")
	s1, _ := NewHMACSigner(key, "k1")
	e1, err := New(dir, s1)
	if err != nil {
		t.Fatalf("new1: %v", err)
	}
	for i := 0; i < 3; i++ {
		e1.Append(sampleEvent(i)) //nolint:errcheck
	}
	e1.Seal()  //nolint:errcheck
	e1.Close() //nolint:errcheck

	// Reopen: must restore seq/chain and keep appending to the same chain.
	s2, _ := NewHMACSigner(key, "k1")
	e2, err := New(dir, s2)
	if err != nil {
		t.Fatalf("new2: %v", err)
	}
	rec, err := e2.Append(sampleEvent(99))
	if err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	if rec.Seq != 4 {
		t.Fatalf("expected seq 4 after reopen, got %d", rec.Seq)
	}
	e2.Close() //nolint:errcheck

	s3, _ := NewHMACSigner(key, "k1")
	rep, err := Verify(dir, s3)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK || rep.Records != 4 {
		t.Fatalf("post-reopen verify failed: %+v", rep)
	}
}

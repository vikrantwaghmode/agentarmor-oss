package report

import (
	"archive/zip"
	"bytes"
	"testing"

	"agentarmor/compliance/audit"
)

func buildLog(t *testing.T) (string, audit.SealSigner) {
	t.Helper()
	dir := t.TempDir()
	signer, err := audit.NewHMACSigner([]byte("report-test-key-0123456789abcdef"), "k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	e, err := audit.New(dir, signer)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	add := func(layer audit.Layer, action, outcome, rule string) {
		ev := audit.NewEvent(layer, action, outcome)
		ev.SessionID = "sess-1"
		ev.RuleMatched = rule
		if _, err := e.Append(ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	add(audit.LayerIngestion, "scan", "BLOCKED", "Prompt Injection: jailbreak")
	add(audit.LayerOutput, "scan", "REDACTED", "Secret Redacted: api_key")
	add(audit.LayerOutput, "scan", "REDACTED", "Payment Data Masked (PCI DSS Req.3): PAN[1×Visa]")
	add(audit.LayerExecution, "tool_call", "ALLOWED", "")
	add(audit.LayerPlanning, "scan", "BLOCKED", "Zero-Trust: tool 'exec' requires approval")
	add(audit.LayerIdentity, "hitl_decision", "approved", "operator-signed HITL decision")
	add(audit.LayerExecution, "scan", "BLOCKED", "Blast Radius Exceeded: total tool calls cap")
	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return dir, signer
}

func TestBuildModel(t *testing.T) {
	dir, signer := buildLog(t)
	m, err := Build(dir, signer)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !m.Integrity.Verified {
		t.Fatalf("expected verified log, problems: %v", m.Integrity.Problems)
	}
	if m.TotalEvents != 7 {
		t.Fatalf("expected 7 events, got %d", m.TotalEvents)
	}
	op, total := m.Coverage()
	if total == 0 || op == 0 {
		t.Fatalf("expected some operating controls, got %d/%d", op, total)
	}
	// Every operating control must carry at least one hash-bearing sample.
	for _, c := range m.Controls {
		if c.EvidenceCount > 0 {
			if len(c.Samples) == 0 || c.Samples[0].Hash == "" {
				t.Fatalf("control %s has evidence but no hash lineage", c.ID)
			}
		}
	}
}

func TestFrameworkFilter(t *testing.T) {
	dir, signer := buildLog(t)
	m, err := Build(dir, signer, SOC2)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, c := range m.Controls {
		if c.Framework != SOC2 {
			t.Fatalf("framework filter leaked: %s", c.Framework)
		}
	}
}

func TestRenderPDF(t *testing.T) {
	dir, signer := buildLog(t)
	m, _ := Build(dir, signer)
	var buf bytes.Buffer
	if err := WritePDF(m, &buf); err != nil {
		t.Fatalf("pdf: %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF")) {
		t.Fatal("output is not a PDF")
	}
	if buf.Len() < 1000 {
		t.Fatalf("PDF suspiciously small: %d bytes", buf.Len())
	}
}

func TestRenderDOCX(t *testing.T) {
	dir, signer := buildLog(t)
	m, _ := Build(dir, signer)
	var buf bytes.Buffer
	if err := WriteDOCX(m, &buf); err != nil {
		t.Fatalf("docx: %v", err)
	}
	// A .docx must be a valid zip containing word/document.xml.
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("docx is not a valid zip: %v", err)
	}
	found := false
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			found = true
		}
	}
	if !found {
		t.Fatal("docx missing word/document.xml")
	}
}

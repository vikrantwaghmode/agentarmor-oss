package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/go-pdf/fpdf"
)

// WritePDF renders the report model to a PDF document (auditor-ready). Evidence
// hashes are printed so the statistics trace back to the tamper-evident log.
func WritePDF(m *ReportModel, w io.Writer) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(16, 16, 16)
	pdf.SetAutoPageBreak(true, 16)
	pdf.AddPage()

	purple := func() { pdf.SetTextColor(124, 58, 237) }
	dark := func() { pdf.SetTextColor(30, 30, 30) }
	gray := func() { pdf.SetTextColor(110, 110, 110) }

	// ── Title ──
	purple()
	pdf.SetFont("Helvetica", "B", 20)
	pdf.CellFormat(0, 10, "AgentArmor Compliance Report", "", 1, "L", false, 0, "")
	gray()
	pdf.SetFont("Helvetica", "", 9)
	fw := "All frameworks"
	if len(m.Frameworks) > 0 {
		fw = ""
		for i, f := range m.Frameworks {
			if i > 0 {
				fw += ", "
			}
			fw += string(f)
		}
	}
	pdf.CellFormat(0, 5, "Frameworks: "+fw, "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 5, "Generated: "+m.GeneratedAt, "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 5, fmt.Sprintf("Evidence period: %s  to  %s", orNA(m.PeriodStart), orNA(m.PeriodEnd)), "", 1, "L", false, 0, "")
	pdf.Ln(3)

	// ── Cryptographic integrity ──
	dark()
	pdf.SetFont("Helvetica", "B", 13)
	pdf.CellFormat(0, 7, "1. Cryptographic Integrity (BLAKE3 + Merkle + HMAC)", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	status := "VERIFIED — log is tamper-evident and intact"
	if !m.Integrity.Verified {
		pdf.SetTextColor(200, 40, 40)
		status = "FAILED — integrity problems detected (see below)"
	} else {
		pdf.SetTextColor(20, 140, 60)
	}
	pdf.CellFormat(0, 6, "Status: "+status, "", 1, "L", false, 0, "")
	dark()
	pdf.CellFormat(0, 6, fmt.Sprintf("Records: %d    Merkle seals: %d    Sealed records: %d",
		m.Integrity.Records, m.Integrity.Seals, m.Integrity.SealedRecords), "", 1, "L", false, 0, "")
	if len(m.Integrity.Problems) > 0 {
		pdf.SetTextColor(200, 40, 40)
		pdf.SetFont("Helvetica", "", 9)
		for _, p := range m.Integrity.Problems {
			pdf.MultiCell(0, 5, " - "+p, "", "L", false)
		}
	}
	pdf.Ln(2)

	// ── Summary ──
	dark()
	pdf.SetFont("Helvetica", "B", 13)
	op, total := m.Coverage()
	pdf.CellFormat(0, 7, "2. Summary", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(0, 6, fmt.Sprintf("Total audited events: %d", m.TotalEvents), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 6, fmt.Sprintf("Controls with operating evidence: %d of %d", op, total), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 6, "Events by outcome: "+joinCounts(m.ByOutcome), "", 1, "L", false, 0, "")
	pdf.Ln(2)

	// ── Control mapping ──
	dark()
	pdf.SetFont("Helvetica", "B", 13)
	pdf.CellFormat(0, 7, "3. Control Mapping & Evidence", "", 1, "L", false, 0, "")
	pdf.Ln(1)

	for _, c := range m.Controls {
		// Header row
		pdf.SetFont("Helvetica", "B", 11)
		purple()
		pdf.CellFormat(0, 6, fmt.Sprintf("%s  %s — %s", c.Framework, c.ID, c.Title), "", 1, "L", false, 0, "")
		dark()
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(0, 4.5, c.Description, "", "L", false)
		if c.EvidenceCount > 0 {
			pdf.SetTextColor(20, 140, 60)
		} else {
			gray()
		}
		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(0, 5, fmt.Sprintf("%s — %d evidence event(s)", c.Status, c.EvidenceCount), "", 1, "L", false, 0, "")

		// Evidence samples with hashes
		gray()
		pdf.SetFont("Courier", "", 7.5)
		for _, ev := range c.Samples {
			line := fmt.Sprintf("seq %d  %s  %s  hash=%s", ev.Seq, ev.Timestamp, ev.Outcome, short(ev.Hash))
			if ev.Rule != "" {
				line += "  (" + ev.Rule + ")"
			}
			pdf.MultiCell(0, 4, line, "", "L", false)
		}
		pdf.Ln(2)
	}

	// Footer note
	gray()
	pdf.SetFont("Helvetica", "I", 8)
	pdf.MultiCell(0, 4, "Each evidence hash is the BLAKE3 chain link (rec_hash) of the originating audit record. "+
		"Re-run AgentArmor's audit verification to confirm these hashes resolve against the signed Merkle seals.", "", "L", false)

	return pdf.Output(w)
}

func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}

func joinCounts(m map[string]int) string {
	if len(m) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s=%d", k, m[k])
	}
	return out
}

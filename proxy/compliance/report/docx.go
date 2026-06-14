package report

import (
	"archive/zip"
	"fmt"
	"html"
	"io"
	"strings"
)

// WriteDOCX renders the report to a minimal, valid Office Open XML (.docx)
// document using only the standard library: a .docx is a ZIP of XML parts, so
// no third-party Word library (and its licensing) is needed.
func WriteDOCX(m *ReportModel, w io.Writer) error {
	zw := zip.NewWriter(w)

	parts := map[string]string{
		"[Content_Types].xml": contentTypesXML,
		"_rels/.rels":         relsXML,
		"word/document.xml":   buildDocumentXML(m),
	}
	for name, body := range parts {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(f, body); err != nil {
			return err
		}
	}
	return zw.Close()
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`

const relsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

// para builds a Word paragraph run. size is half-points (e.g. 28 = 14pt).
func para(text string, bold bool, size int, color string) string {
	rpr := fmt.Sprintf("<w:sz w:val=\"%d\"/>", size)
	if bold {
		rpr += "<w:b/>"
	}
	if color != "" {
		rpr += fmt.Sprintf("<w:color w:val=\"%s\"/>", color)
	}
	return fmt.Sprintf(
		"<w:p><w:pPr><w:rPr>%s</w:rPr></w:pPr><w:r><w:rPr>%s</w:rPr><w:t xml:space=\"preserve\">%s</w:t></w:r></w:p>",
		rpr, rpr, html.EscapeString(text),
	)
}

func mono(text string) string {
	return fmt.Sprintf(
		"<w:p><w:r><w:rPr><w:rFonts w:ascii=\"Consolas\" w:hAnsi=\"Consolas\"/><w:sz w:val=\"15\"/><w:color w:val=\"666666\"/></w:rPr><w:t xml:space=\"preserve\">%s</w:t></w:r></w:p>",
		html.EscapeString(text),
	)
}

func buildDocumentXML(m *ReportModel) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)

	b.WriteString(para("AgentArmor Compliance Report", true, 40, "7C3AED"))
	fw := "All frameworks"
	if len(m.Frameworks) > 0 {
		var fs []string
		for _, f := range m.Frameworks {
			fs = append(fs, string(f))
		}
		fw = strings.Join(fs, ", ")
	}
	b.WriteString(para("Frameworks: "+fw, false, 18, "666666"))
	b.WriteString(para("Generated: "+m.GeneratedAt, false, 18, "666666"))
	b.WriteString(para(fmt.Sprintf("Evidence period: %s to %s", orNA(m.PeriodStart), orNA(m.PeriodEnd)), false, 18, "666666"))

	// Integrity
	b.WriteString(para("1. Cryptographic Integrity (BLAKE3 + Merkle + HMAC)", true, 26, "1E1E1E"))
	if m.Integrity.Verified {
		b.WriteString(para("Status: VERIFIED — log is tamper-evident and intact", true, 20, "148C3C"))
	} else {
		b.WriteString(para("Status: FAILED — integrity problems detected", true, 20, "C82828"))
	}
	b.WriteString(para(fmt.Sprintf("Records: %d   Merkle seals: %d   Sealed records: %d",
		m.Integrity.Records, m.Integrity.Seals, m.Integrity.SealedRecords), false, 18, ""))
	for _, p := range m.Integrity.Problems {
		b.WriteString(para(" - "+p, false, 16, "C82828"))
	}

	// Summary
	op, total := m.Coverage()
	b.WriteString(para("2. Summary", true, 26, "1E1E1E"))
	b.WriteString(para(fmt.Sprintf("Total audited events: %d", m.TotalEvents), false, 18, ""))
	b.WriteString(para(fmt.Sprintf("Controls with operating evidence: %d of %d", op, total), false, 18, ""))
	b.WriteString(para("Events by outcome: "+joinCounts(m.ByOutcome), false, 18, ""))

	// Controls
	b.WriteString(para("3. Control Mapping & Evidence", true, 26, "1E1E1E"))
	for _, c := range m.Controls {
		b.WriteString(para(fmt.Sprintf("%s  %s — %s", c.Framework, c.ID, c.Title), true, 22, "7C3AED"))
		b.WriteString(para(c.Description, false, 17, ""))
		color := "888888"
		if c.EvidenceCount > 0 {
			color = "148C3C"
		}
		b.WriteString(para(fmt.Sprintf("%s — %d evidence event(s)", c.Status, c.EvidenceCount), true, 17, color))
		for _, ev := range c.Samples {
			line := fmt.Sprintf("seq %d  %s  %s  hash=%s", ev.Seq, ev.Timestamp, ev.Outcome, short(ev.Hash))
			if ev.Rule != "" {
				line += "  (" + ev.Rule + ")"
			}
			b.WriteString(mono(line))
		}
	}

	b.WriteString(para("Each evidence hash is the BLAKE3 chain link (rec_hash) of the originating audit record; "+
		"re-run AgentArmor's audit verification to confirm it resolves against the signed Merkle seals.", false, 14, "888888"))

	b.WriteString(`</w:body></w:document>`)
	return b.String()
}

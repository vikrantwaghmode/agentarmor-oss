package report

import (
	"sort"
	"time"

	"agentarmor/compliance/audit"
)

// IntegritySummary is the cryptographic verification result for the period —
// the foundation every other statistic rests on (a report over a tampered log
// is worthless, so this is surfaced first).
type IntegritySummary struct {
	Verified      bool
	Records       int
	Seals         int
	SealedRecords int
	Problems      []string
}

// Evidence is one audit record backing a control, with its BLAKE3 chain hash so
// an auditor can trace the statistic to the exact tamper-evident entry.
type Evidence struct {
	Seq       uint64
	Timestamp string
	Outcome   string
	Rule      string
	Hash      string // rec_hash (chain link) — the verifiable lineage anchor
}

// ControlResult is a control plus the evidence found for it in the period.
type ControlResult struct {
	ID            string
	Framework     Framework
	Title         string
	Description   string
	EvidenceCount int
	Status        string // "Operating" | "No evidence in period"
	Samples       []Evidence
}

// ReportModel is the fully-analyzed, render-agnostic report.
type ReportModel struct {
	GeneratedAt string
	PeriodStart string
	PeriodEnd   string
	Frameworks  []Framework
	Integrity   IntegritySummary
	TotalEvents int
	ByOutcome   map[string]int
	ByLayer     map[string]int
	Controls    []ControlResult
}

const maxSamples = 5

// Build loads the sealed audit log in dir, verifies it with signer, and maps
// events onto controls. If frameworks is non-empty, only those frameworks'
// controls are included.
func Build(dir string, signer audit.SealSigner, frameworks ...Framework) (*ReportModel, error) {
	records, err := audit.ReadRecords(dir)
	if err != nil {
		return nil, err
	}
	vr, err := audit.Verify(dir, signer)
	if err != nil {
		return nil, err
	}

	m := &ReportModel{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Frameworks:  frameworks,
		Integrity: IntegritySummary{
			Verified:      vr.OK,
			Records:       vr.Records,
			Seals:         vr.Seals,
			SealedRecords: vr.SealedRecords,
			Problems:      vr.Problems,
		},
		TotalEvents: len(records),
		ByOutcome:   map[string]int{},
		ByLayer:     map[string]int{},
	}

	for _, r := range records {
		if m.PeriodStart == "" || r.Event.Timestamp < m.PeriodStart {
			m.PeriodStart = r.Event.Timestamp
		}
		if r.Event.Timestamp > m.PeriodEnd {
			m.PeriodEnd = r.Event.Timestamp
		}
		m.ByOutcome[r.Event.Outcome]++
		m.ByLayer[string(r.Event.Layer)]++
	}

	want := func(f Framework) bool {
		if len(frameworks) == 0 {
			return true
		}
		for _, x := range frameworks {
			if x == f {
				return true
			}
		}
		return false
	}

	for _, c := range Catalog() {
		if !want(c.Framework) {
			continue
		}
		cr := ControlResult{ID: c.ID, Framework: c.Framework, Title: c.Title, Description: c.Description, Status: "No evidence in period"}
		for _, r := range records {
			if !c.Match(r.Event) {
				continue
			}
			cr.EvidenceCount++
			if len(cr.Samples) < maxSamples {
				cr.Samples = append(cr.Samples, Evidence{
					Seq:       r.Seq,
					Timestamp: r.Event.Timestamp,
					Outcome:   r.Event.Outcome,
					Rule:      r.Event.RuleMatched,
					Hash:      r.RecHash,
				})
			}
		}
		if cr.EvidenceCount > 0 {
			cr.Status = "Operating"
		}
		m.Controls = append(m.Controls, cr)
	}

	// Stable order: framework then control id.
	sort.SliceStable(m.Controls, func(i, j int) bool {
		if m.Controls[i].Framework != m.Controls[j].Framework {
			return m.Controls[i].Framework < m.Controls[j].Framework
		}
		return m.Controls[i].ID < m.Controls[j].ID
	})
	return m, nil
}

// Coverage returns how many controls have at least one piece of evidence.
func (m *ReportModel) Coverage() (operating, total int) {
	total = len(m.Controls)
	for _, c := range m.Controls {
		if c.EvidenceCount > 0 {
			operating++
		}
	}
	return
}

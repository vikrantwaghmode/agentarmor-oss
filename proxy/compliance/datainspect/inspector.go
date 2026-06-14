package datainspect

import "sort"

// Inspector runs PAN + SAD discovery and deterministic masking over text.
// The zero value is usable (all detectors on); construct via New for clarity.
type Inspector struct {
	DetectPAN bool
	DetectSAD bool
}

// New returns an Inspector with all detectors enabled.
func New() *Inspector { return &Inspector{DetectPAN: true, DetectSAD: true} }

// Result is the outcome of inspecting a string.
type Result struct {
	Masked   string     // text with PAN masked + SAD purged
	PANs     []PANMatch // validated PANs found (offsets into the ORIGINAL text)
	SAD      []SADMatch // SAD found (offsets into the ORIGINAL text)
	Modified bool       // true if Masked differs from the input
}

// Found reports whether any payment data was discovered.
func (r Result) Found() bool { return len(r.PANs) > 0 || len(r.SAD) > 0 }

func sadToken(k SADKind) string {
	switch k {
	case SADTrack1, SADTrack2:
		return "[TRACK_DATA_REDACTED]"
	default: // CVV / PIN — only the numeric group is the span
		return "***"
	}
}

type span struct {
	start, end int
	with       string
}

// Inspect finds and masks payment data. PAN is masked to last-4; SAD is fully
// purged. Overlapping spans (e.g. a PAN embedded inside magnetic track data)
// are resolved by preferring the longer, earlier span so track data is redacted
// as a unit rather than partially masked.
func (ins *Inspector) Inspect(text string) Result {
	res := Result{Masked: text}
	var spans []span

	if ins.DetectSAD {
		res.SAD = FindSAD(text)
		for _, m := range res.SAD {
			spans = append(spans, span{m.Start, m.End, sadToken(m.Kind)})
		}
	}
	if ins.DetectPAN {
		res.PANs = FindPANs(text)
		for _, p := range res.PANs {
			spans = append(spans, span{p.Start, p.End, maskPAN(text[p.Start:p.End])})
		}
	}
	if len(spans) == 0 {
		return res
	}

	// Order by start; on ties, the longer span first so it wins overlap
	// resolution (track data outranks an inner PAN candidate).
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return (spans[i].end - spans[i].start) > (spans[j].end - spans[j].start)
	})

	var b []byte
	cursor := 0
	for _, s := range spans {
		if s.start < cursor { // overlaps an already-applied replacement — skip
			continue
		}
		b = append(b, text[cursor:s.start]...)
		b = append(b, s.with...)
		cursor = s.end
	}
	b = append(b, text[cursor:]...)

	res.Masked = string(b)
	res.Modified = res.Masked != text
	return res
}

// Package datainspect implements AgentArmor's deep data inspection for payment
// data (Compliance Phase 3 — PCI DSS Requirement 3).
//
// It discovers Primary Account Numbers (PAN) and Sensitive Authentication Data
// (SAD — CVV/CVC, magnetic-stripe track data, PIN blocks) in free text (and, via
// ocr.go, in scanned images/PDFs), then deterministically masks them BEFORE the
// data is committed to disk, written to the audit log, or appended to the LLM
// context window. PAN is masked to PCI's "first-6/last-4 max" rule; SAD is fully
// purged because PCI Req. 3.2 forbids storing it after authorization at all.
//
// Detection is a regex candidate-finder followed by a Luhn check, which keeps
// false positives low without an ML model (an optional ML classifier can be
// layered in front as the report suggests; the Luhn fallback is the
// deterministic guarantee).
package datainspect

import "regexp"

// panCandidate matches 13–19 digit runs allowing single space/hyphen group
// separators (so "4111 1111 1111 1111" and "4111-1111-1111-1111" are caught).
// Candidates are Luhn-validated before being treated as PANs.
var panCandidate = regexp.MustCompile(`\d(?:[ -]?\d){11,17}\d`)

// Brand classifies a validated PAN by its issuer pattern (for reporting only;
// masking does not depend on it).
type Brand string

const (
	Visa       Brand = "Visa"
	Mastercard Brand = "Mastercard"
	Amex       Brand = "American Express"
	Discover   Brand = "Discover"
	Diners     Brand = "Diners Club"
	JCB        Brand = "JCB"
	UnknownPAN Brand = "Unknown"
)

// PANMatch is a validated PAN occurrence located in the source text.
type PANMatch struct {
	Start  int    // byte offset of the match in the source
	End    int    // byte offset (exclusive)
	Brand  Brand  // detected card brand
	Last4  string // last four digits (the only part PCI lets you retain freely)
	Digits int    // number of digits (13–19)
}

// luhnValid reports whether the digit string passes the Luhn checksum.
func luhnValid(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// onlyDigits strips spaces/hyphens, returning the bare digit string.
func onlyDigits(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// classifyBrand returns the card brand for a bare digit string.
func classifyBrand(d string) Brand {
	n := len(d)
	switch {
	case n >= 13 && d[0] == '4':
		return Visa
	case n == 15 && (d[:2] == "34" || d[:2] == "37"):
		return Amex
	case n == 16 && d[:2] >= "51" && d[:2] <= "55":
		return Mastercard
	case n == 16 && d[:4] >= "2221" && d[:4] <= "2720":
		return Mastercard
	case n == 16 && (d[:4] == "6011" || d[:2] == "65"):
		return Discover
	case n == 16 && d[:3] >= "644" && d[:3] <= "649":
		return Discover
	case (n == 14) && (d[:2] == "36" || d[:2] == "38" || (d[:3] >= "300" && d[:3] <= "305")):
		return Diners
	case n == 16 && d[:2] == "35":
		return JCB
	default:
		return UnknownPAN
	}
}

// FindPANs returns every Luhn-valid PAN candidate in text, in order.
func FindPANs(text string) []PANMatch {
	var out []PANMatch
	for _, loc := range panCandidate.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		digits := onlyDigits(raw)
		if len(digits) < 13 || len(digits) > 19 {
			continue
		}
		if !luhnValid(digits) {
			continue
		}
		out = append(out, PANMatch{
			Start:  loc[0],
			End:    loc[1],
			Brand:  classifyBrand(digits),
			Last4:  digits[len(digits)-4:],
			Digits: len(digits),
		})
	}
	return out
}

// maskPAN masks a matched PAN substring per PCI Req. 3.4: every digit except the
// last four becomes '*', while separators are preserved so the field stays
// recognizable (e.g. "****-****-****-1234").
func maskPAN(raw string) string {
	total := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] >= '0' && raw[i] <= '9' {
			total++
		}
	}
	keepFrom := total - 4
	out := []byte(raw)
	seen := 0
	for i := 0; i < len(out); i++ {
		if out[i] >= '0' && out[i] <= '9' {
			if seen < keepFrom {
				out[i] = '*'
			}
			seen++
		}
	}
	return string(out)
}

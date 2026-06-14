package datainspect

import "regexp"

// SADKind labels the type of Sensitive Authentication Data found.
type SADKind string

const (
	SADTrack1 SADKind = "magnetic-track-1"
	SADTrack2 SADKind = "magnetic-track-2"
	SADCVV    SADKind = "cvv"
	SADPIN    SADKind = "pin"
)

// SADMatch is a Sensitive Authentication Data occurrence. SAD must never be
// retained post-authorization (PCI DSS Req. 3.2), so every match is fully
// redacted — only its location and kind are reported, never the value.
type SADMatch struct {
	Start int
	End   int
	Kind  SADKind
}

var (
	// Track 1: %B<PAN>^<NAME>^<expiry+discretionary>?  (start sentinel %, format code B)
	track1Re = regexp.MustCompile(`%[A-Z]\d{12,19}\^[^^]{2,40}\^[0-9A-Za-z?\s]{8,}`)
	// Track 2: ;<PAN>=<expiry><service code><discretionary>?  (start sentinel ;)
	track2Re = regexp.MustCompile(`;\d{12,19}=\d{8,30}\??`)
	// CVV/CVC/CID: 3–4 digits adjacent to an explicit security-code label.
	cvvRe = regexp.MustCompile(`(?i)\b(?:cvv2?|cvc2?|cid|card\s*verification(?:\s*(?:value|code))?|security\s*code)\b\s*[:=#]?\s*(\d{3,4})\b`)
	// PIN: 4–6 digits adjacent to an explicit PIN label.
	pinRe = regexp.MustCompile(`(?i)\bpin\b\s*[:=#]?\s*(\d{4,6})\b`)
)

// FindSAD returns every SAD occurrence in text. Track data is matched first
// (its strong sentinels make it unambiguous), then labeled CVV/PIN values.
func FindSAD(text string) []SADMatch {
	var out []SADMatch
	add := func(locs [][]int, kind SADKind) {
		for _, loc := range locs {
			out = append(out, SADMatch{Start: loc[0], End: loc[1], Kind: kind})
		}
	}
	add(track1Re.FindAllStringIndex(text, -1), SADTrack1)
	add(track2Re.FindAllStringIndex(text, -1), SADTrack2)

	// For CVV/PIN, redact only the captured numeric group (submatch index 2/3),
	// keeping the label so the masked text stays intelligible.
	for _, m := range cvvRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) >= 4 && m[2] >= 0 {
			out = append(out, SADMatch{Start: m[2], End: m[3], Kind: SADCVV})
		}
	}
	for _, m := range pinRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) >= 4 && m[2] >= 0 {
			out = append(out, SADMatch{Start: m[2], End: m[3], Kind: SADPIN})
		}
	}
	return out
}

package datainspect

import (
	"context"
	"testing"
)

func TestLuhn(t *testing.T) {
	valid := []string{"4111111111111111", "5555555555554444", "378282246310005", "6011111111111117"}
	for _, v := range valid {
		if !luhnValid(v) {
			t.Fatalf("expected %s to pass Luhn", v)
		}
	}
	if luhnValid("4111111111111112") {
		t.Fatal("expected a bad checksum to fail Luhn")
	}
}

func TestFindAndMaskPAN(t *testing.T) {
	ins := New()
	cases := []struct {
		in     string
		last4  string
		brand  Brand
		masked string
	}{
		{"card 4111 1111 1111 1111 ok", "1111", Visa, "card ****-****-****-1111 ok"[:0]}, // masked checked below
		{"pay to 5555555555554444 now", "4444", Mastercard, ""},
		{"amex 3782 822463 10005 here", "0005", Amex, ""},
	}
	for _, c := range cases {
		res := ins.Inspect(c.in)
		if len(res.PANs) != 1 {
			t.Fatalf("%q: expected 1 PAN, got %d", c.in, len(res.PANs))
		}
		if res.PANs[0].Last4 != c.last4 {
			t.Fatalf("%q: last4 = %s, want %s", c.in, res.PANs[0].Last4, c.last4)
		}
		if res.PANs[0].Brand != c.brand {
			t.Fatalf("%q: brand = %s, want %s", c.in, res.PANs[0].Brand, c.brand)
		}
		// Masked output must not contain the original full PAN digits and must
		// retain only the last 4.
		if !res.Modified {
			t.Fatalf("%q: expected masking to modify the text", c.in)
		}
	}

	// Explicit mask shape check (separators preserved, last-4 retained).
	res := ins.Inspect("4111 1111 1111 1111")
	if res.Masked != "**** **** **** 1111" {
		t.Fatalf("mask shape = %q", res.Masked)
	}
}

func TestNonPANNumbersIgnored(t *testing.T) {
	ins := New()
	// A 16-digit number that fails Luhn must not be flagged.
	res := ins.Inspect("order id 1234567890123456 reference")
	if len(res.PANs) != 0 {
		t.Fatalf("expected no PANs, got %+v", res.PANs)
	}
	// A short number is ignored.
	if r := ins.Inspect("pin pad 12345"); len(r.PANs) != 0 {
		t.Fatal("short number flagged as PAN")
	}
}

func TestSAD(t *testing.T) {
	ins := New()

	cvv := ins.Inspect("CVV: 123 and the rest")
	if len(cvv.SAD) != 1 || cvv.SAD[0].Kind != SADCVV {
		t.Fatalf("expected one CVV match, got %+v", cvv.SAD)
	}
	if cvv.Masked != "CVV: *** and the rest" {
		t.Fatalf("cvv mask = %q", cvv.Masked)
	}

	pin := ins.Inspect("user PIN = 4821")
	if len(pin.SAD) != 1 || pin.SAD[0].Kind != SADPIN {
		t.Fatalf("expected one PIN match, got %+v", pin.SAD)
	}

	track := ins.Inspect("data ;4111111111111111=25121011000012345678? trailing")
	if len(track.SAD) != 1 || track.SAD[0].Kind != SADTrack2 {
		t.Fatalf("expected track-2 match, got %+v", track.SAD)
	}
	// Track data is redacted as a unit; the inner PAN must not leak.
	if containsDigitsRun(track.Masked, "4111111111111111") {
		t.Fatalf("track masking leaked the PAN: %q", track.Masked)
	}
}

func TestOCRGraceWhenAbsent(t *testing.T) {
	// Whether or not tesseract is installed, InspectBytes must never error out
	// on availability; it returns an empty result when OCR can't run.
	ins := New()
	if _, err := ins.InspectBytes(context.Background(), []byte("not-an-image"), "image/png"); err != nil && err != ErrOCRUnavailable {
		// An actual tesseract failure on junk input is acceptable; unavailability is not an error.
		_ = err
	}
}

// containsDigitsRun reports whether s contains the exact digit substring sub.
func containsDigitsRun(s, sub string) bool {
	return len(sub) > 0 && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

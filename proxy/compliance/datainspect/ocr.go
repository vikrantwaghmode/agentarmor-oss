package datainspect

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// OCR lets the inspector reach payment data hidden inside scanned documents and
// rotated images — the gap a text-only scanner misses (PCI data discovery).
//
// OCR is the one piece no language does natively, so we shell out to the
// industry-standard Tesseract binary (and pdftoppm for PDFs), matching the
// existing doc2md subprocess pattern. When the binaries are absent, OCR is a
// graceful no-op: text-layer inspection still runs, and the engine never fails
// the request because OCR was unavailable.

// ErrOCRUnavailable is returned when the tesseract binary is not installed.
var ErrOCRUnavailable = errors.New("datainspect: tesseract not available")

// ocrTimeout bounds a single OCR invocation so a malformed file can't hang the
// pipeline (also a Phase-1/L5 availability safeguard).
const ocrTimeout = 20 * time.Second

// OCRAvailable reports whether the tesseract binary is on PATH.
func OCRAvailable() bool {
	_, err := exec.LookPath("tesseract")
	return err == nil
}

// pdfSupportAvailable reports whether pdftoppm (poppler-utils) is present for
// rasterizing PDF pages before OCR.
func pdfSupportAvailable() bool {
	_, err := exec.LookPath("pdftoppm")
	return err == nil
}

// OCRImageBytes runs Tesseract over a single raster image (PNG/JPG/TIFF/…) and
// returns the recognized text. Uses --psm 3 (default page segmentation) which
// handles rotated/multi-block scans reasonably.
func OCRImageBytes(ctx context.Context, img []byte) (string, error) {
	if !OCRAvailable() {
		return "", ErrOCRUnavailable
	}
	dir, err := os.MkdirTemp("", "aa-ocr-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	in := filepath.Join(dir, "in.img")
	if err := os.WriteFile(in, img, 0o600); err != nil {
		return "", err
	}

	cctx, cancel := context.WithTimeout(ctx, ocrTimeout)
	defer cancel()
	// "stdout" makes tesseract emit recognized text to stdout.
	out, err := exec.CommandContext(cctx, "tesseract", in, "stdout", "--psm", "3").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// OCRPDFBytes rasterizes a PDF to grayscale PNGs (pdftoppm) and OCRs each page,
// returning the concatenated text. Falls back to ErrOCRUnavailable if either
// tool is missing.
func OCRPDFBytes(ctx context.Context, pdf []byte) (string, error) {
	if !OCRAvailable() || !pdfSupportAvailable() {
		return "", ErrOCRUnavailable
	}
	dir, err := os.MkdirTemp("", "aa-ocrpdf-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	in := filepath.Join(dir, "in.pdf")
	if err := os.WriteFile(in, pdf, 0o600); err != nil {
		return "", err
	}

	cctx, cancel := context.WithTimeout(ctx, ocrTimeout*3) // multi-page budget
	defer cancel()
	prefix := filepath.Join(dir, "page")
	if err := exec.CommandContext(cctx, "pdftoppm", "-png", "-gray", "-r", "200", in, prefix).Run(); err != nil {
		return "", err
	}

	pages, _ := filepath.Glob(prefix + "*.png")
	var sb strings.Builder
	for _, p := range pages {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		txt, err := OCRImageBytes(cctx, b)
		if err != nil {
			continue
		}
		sb.WriteString(txt)
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// InspectBytes OCRs an attachment (by content type hint) and inspects the
// recognized text for payment data. contentType may be a MIME type or filename
// extension; anything containing "pdf" is treated as a PDF, otherwise it is
// OCR'd as an image. Returns a zero Result (not an error) when OCR is
// unavailable, so callers degrade gracefully.
func (ins *Inspector) InspectBytes(ctx context.Context, data []byte, contentType string) (Result, error) {
	var (
		text string
		err  error
	)
	if strings.Contains(strings.ToLower(contentType), "pdf") {
		text, err = OCRPDFBytes(ctx, data)
	} else {
		text, err = OCRImageBytes(ctx, data)
	}
	if errors.Is(err, ErrOCRUnavailable) {
		return Result{}, nil
	}
	if err != nil {
		return Result{}, err
	}
	return ins.Inspect(text), nil
}

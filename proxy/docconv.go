package main

// Document conversion layer — converts file uploads (PDF, Word, Excel,
// PowerPoint) embedded in chat-completion requests to Markdown via doc2md
// (https://github.com/vikrantwaghmode/doc2md) before they reach the LLM.
//
// Why: binary document formats bypass AgentArmor's text-based scanners
// entirely (a prompt injection or exfiltration payload hidden inside a PDF
// sails straight through), and they cost far more LLM tokens than the
// equivalent Markdown. Converting to Markdown first means the existing
// scanPayload() pipeline can inspect the actual document content, and the
// LLM receives a smaller, cleaner representation.
//
// doc2md is invoked as a subprocess (CLI). It must be installed in the
// runtime image (see Dockerfile) for this feature to do anything; if the
// binary isn't on PATH, conversion is skipped and the original upload passes
// through untouched.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ─── Policy section ───────────────────────────────────────────────────────────

type DocConversionConfig struct {
	Enabled        bool `yaml:"enabled" json:"enabled"`
	MaxFileSizeMB  int  `yaml:"max_file_size_mb" json:"max_file_size_mb"`
	TimeoutSeconds int  `yaml:"timeout_seconds" json:"timeout_seconds"`
}

// ─── format detection ─────────────────────────────────────────────────────────

// docExtByMime maps the MIME types LLM chat APIs attach to uploaded documents
// to the file extension doc2md needs to pick the right converter.
var docExtByMime = map[string]string{
	"application/pdf": ".pdf",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   ".docx",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         ".xlsx",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
	"application/vnd.ms-excel":  ".xls",
	"text/csv":                  ".csv",
	"text/tab-separated-values": ".tsv",
}

var docExtRe = regexp.MustCompile(`(?i)\.(pdf|docx|pptx|xlsx|xls|csv|tsv)$`)

var dataURIRe = regexp.MustCompile(`^data:([^;,]+)(?:;[^,]*)?;base64,(.+)$`)

// extToMime is only used to recognize a filename when no MIME type was sent.
func extFromFilename(name string) string {
	m := docExtRe.FindStringSubmatch(strings.ToLower(name))
	if len(m) == 2 {
		return "." + m[1]
	}
	return ""
}

func extFromMime(mime string) string {
	mime = strings.ToLower(strings.TrimSpace(mime))
	if ext, ok := docExtByMime[mime]; ok {
		return ext
	}
	return ""
}

// docAttachment is what we extract from a single chat content block.
type docAttachment struct {
	Filename string
	Ext      string
	Data     []byte
}

// findAttachment inspects a chat-message content block for an embedded
// document. It understands the two shapes LLM APIs commonly use:
//
//	Anthropic:  {"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"..."}}
//	OpenAI:     {"type":"file","file":{"filename":"report.pdf","file_data":"data:application/pdf;base64,..."}}
//
// and falls back to scanning any string field for a `data:<mime>;base64,...`
// URI, which covers other / future shapes without bespoke parsing.
func findAttachment(block map[string]interface{}) (docAttachment, bool) {
	var filename, mime, b64 string

	switch t, _ := block["type"].(string); t {
	case "document", "input_file":
		if src, ok := block["source"].(map[string]interface{}); ok {
			mime, _ = src["media_type"].(string)
			b64, _ = src["data"].(string)
		}
		if name, ok := block["title"].(string); ok {
			filename = name
		}
	case "file":
		if f, ok := block["file"].(map[string]interface{}); ok {
			filename, _ = f["filename"].(string)
			if fd, ok := f["file_data"].(string); ok {
				if m := dataURIRe.FindStringSubmatch(fd); m != nil {
					mime, b64 = m[1], m[2]
				}
			}
		}
	}

	// Generic fallback — look for a data URI in any string field of the block.
	if b64 == "" {
		for _, v := range block {
			if s, ok := v.(string); ok {
				if m := dataURIRe.FindStringSubmatch(s); m != nil {
					mime, b64 = m[1], m[2]
					break
				}
			}
		}
	}
	if b64 == "" {
		return docAttachment{}, false
	}

	ext := extFromFilename(filename)
	if ext == "" {
		ext = extFromMime(mime)
	}
	if ext == "" {
		return docAttachment{}, false // not a document type doc2md supports
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return docAttachment{}, false
	}
	if filename == "" {
		filename = "upload" + ext
	}
	return docAttachment{Filename: filename, Ext: ext, Data: raw}, true
}

// ─── doc2md subprocess ────────────────────────────────────────────────────────

var docConverterChecked = false
var docConverterOK = false

// docConverterAvailable reports whether the `doc2md` CLI is on PATH. Cached
// after the first lookup since PATH doesn't change at runtime.
func docConverterAvailable() bool {
	if !docConverterChecked {
		_, err := exec.LookPath("doc2md")
		docConverterOK = err == nil
		docConverterChecked = true
	}
	return docConverterOK
}

// runDoc2MD writes raw to a temp file with the right extension, shells out to
// `doc2md <file> --stdout`, and returns the converted Markdown.
func runDoc2MD(att docAttachment, timeoutSeconds int) (string, error) {
	tmp, err := os.CreateTemp("", "agentarmor-upload-*"+att.Ext)
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(att.Data); err != nil {
		tmp.Close()
		return "", err
	}
	tmp.Close()

	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "doc2md", tmpPath, "--stdout")
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out.String(), nil
}

// ─── request-body rewrite ─────────────────────────────────────────────────────

// convertDocumentAttachments scans a chat-completion request body for
// embedded PDF/Word/Excel/PowerPoint uploads, converts each to Markdown, and
// replaces the attachment block in place with a plain text block containing
// the Markdown (prefixed with a provenance note). The rewritten payload is
// what gets scanned and forwarded — so DLP/injection scanners see real
// document content, and the LLM receives Markdown instead of a binary blob.
//
// Returns the (possibly unchanged) payload and the filenames it converted.
func convertDocumentAttachments(payload string, cfg DocConversionConfig) (string, []string) {
	if !docConverterAvailable() {
		return payload, nil
	}

	var frame map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &frame); err != nil {
		return payload, nil
	}
	messages, ok := frame["messages"].([]interface{})
	if !ok {
		return payload, nil
	}

	maxBytes := cfg.MaxFileSizeMB * 1024 * 1024
	var converted []string
	anyChanged := false

	for _, m := range messages {
		msg, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		content, ok := msg["content"].([]interface{})
		if !ok {
			continue
		}

		msgChanged := false
		newContent := make([]interface{}, 0, len(content))
		for _, c := range content {
			block, ok := c.(map[string]interface{})
			if !ok {
				newContent = append(newContent, c)
				continue
			}
			att, found := findAttachment(block)
			if !found {
				newContent = append(newContent, c)
				continue
			}
			if maxBytes > 0 && len(att.Data) > maxBytes {
				log.Printf("📄 doc2md: skipping %s — exceeds max_file_size_mb (%d MB)", att.Filename, cfg.MaxFileSizeMB)
				newContent = append(newContent, c)
				continue
			}

			md, err := runDoc2MD(att, cfg.TimeoutSeconds)
			if err != nil {
				log.Printf("⚠️  doc2md: conversion failed for %s: %v", att.Filename, err)
				newContent = append(newContent, c)
				continue
			}

			newContent = append(newContent, map[string]interface{}{
				"type": "text",
				"text": fmt.Sprintf("[AgentArmor: '%s' converted from %s to Markdown for scanning and token efficiency]\n\n%s", att.Filename, strings.TrimPrefix(att.Ext, "."), md),
			})
			converted = append(converted, att.Filename)
			msgChanged = true
		}

		if msgChanged {
			msg["content"] = newContent
			anyChanged = true
		}
	}

	if !anyChanged {
		return payload, nil
	}
	out, err := json.Marshal(frame)
	if err != nil {
		return payload, nil
	}
	return string(out), converted
}

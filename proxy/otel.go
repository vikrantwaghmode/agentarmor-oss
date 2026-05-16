package main

// Minimal OpenTelemetry-compatible tracer — emits spans to any OTLP/HTTP
// endpoint (Jaeger, Grafana Tempo, Honeycomb, Datadog Agent, etc.) using
// only stdlib. No external dependencies.
//
// Configuration (env vars):
//   OTEL_EXPORTER_OTLP_ENDPOINT  e.g. http://jaeger:4318
//   OTEL_SERVICE_NAME             default: "agentarmor"
//   OTEL_INSECURE=true            skip TLS verification (dev only)
//
// Leave OTEL_EXPORTER_OTLP_ENDPOINT empty to disable tracing.
//
// Spans are batched and flushed every 5 seconds or when the batch reaches 100.
//
// Emits:
//   agentarmor.request   — one per HTTP/WS request (method, path, session_key, tenant_id)
//   agentarmor.scan      — result of the scanner pipeline (action, rule_matched)

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// ─── config ───────────────────────────────────────────────────────────────────

var (
	otelEnabled     bool
	otelEndpoint    string
	otelServiceName string
	otelInsecure    bool
	otelBatch       = make(chan *otelSpan, 4096)
	otelSenderOnce  sync.Once
)

func initOTel() {
	otelEndpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if otelEndpoint == "" {
		return
	}
	otelServiceName = os.Getenv("OTEL_SERVICE_NAME")
	if otelServiceName == "" {
		otelServiceName = "agentarmor"
	}
	otelInsecure = os.Getenv("OTEL_INSECURE") == "true"
	otelEnabled = true

	ensureOTelSender()
	log.Printf("✅ OpenTelemetry tracing enabled → %s (service: %s)", otelEndpoint, otelServiceName)
}

// ensureOTelSender starts the background batch sender at most once.
func ensureOTelSender() {
	otelSenderOnce.Do(func() { go otelBatchSender() })
}

// ReinitOTel applies new OTel config from infra.yaml at runtime — no restart needed.
func ReinitOTel(cfg InfraOTel) {
	otelEndpoint = cfg.Endpoint
	otelInsecure = cfg.Insecure
	if cfg.ServiceName != "" {
		otelServiceName = cfg.ServiceName
	} else {
		otelServiceName = "agentarmor"
	}
	otelEnabled = cfg.Enabled && cfg.Endpoint != ""

	if otelEnabled {
		ensureOTelSender() // no-op if already running
		log.Printf("✅ OTel tracing enabled → %s (service: %s)", otelEndpoint, otelServiceName)
	} else {
		log.Printf("🚫 OTel tracing disabled")
	}
}

// ─── span ─────────────────────────────────────────────────────────────────────

type otelSpan struct {
	TraceID   string // 32 hex chars (16 bytes)
	SpanID    string // 16 hex chars (8 bytes)
	ParentID  string // empty if root
	Name      string
	StartNano int64
	EndNano   int64
	Attrs     [][2]string // key, value pairs
	mu        sync.Mutex
}

func newTraceID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

func newSpanID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// startSpan creates a new span. If ctx already carries a span, the new span
// is a child of it. Returns a new context carrying this span.
func startSpan(ctx context.Context, name string) (context.Context, *otelSpan) {
	if !otelEnabled {
		return ctx, &otelSpan{} // no-op
	}

	s := &otelSpan{
		SpanID:    newSpanID(),
		Name:      name,
		StartNano: time.Now().UnixNano(),
	}

	if parent, ok := ctx.Value(otelCtxKey{}).(*otelSpan); ok && parent != nil && parent.TraceID != "" {
		s.TraceID = parent.TraceID
		s.ParentID = parent.SpanID
	} else {
		s.TraceID = newTraceID()
	}

	return context.WithValue(ctx, otelCtxKey{}, s), s
}

type otelCtxKey struct{}

func spanFromCtx(ctx context.Context) *otelSpan {
	if s, ok := ctx.Value(otelCtxKey{}).(*otelSpan); ok {
		return s
	}
	return nil
}

func (s *otelSpan) SetAttr(k, v string) {
	if s == nil || !otelEnabled {
		return
	}
	s.mu.Lock()
	s.Attrs = append(s.Attrs, [2]string{k, v})
	s.mu.Unlock()
}

func (s *otelSpan) End() {
	if s == nil || !otelEnabled || s.TraceID == "" {
		return
	}
	s.EndNano = time.Now().UnixNano()
	select {
	case otelBatch <- s:
	default: // drop if batch is full
	}
}

// TraceIDHex returns the trace ID for use in response headers / audit log.
func (s *otelSpan) TraceIDHex() string {
	if s == nil {
		return ""
	}
	return s.TraceID
}

// ─── HTTP middleware ──────────────────────────────────────────────────────────

// otelMiddleware wraps an http.Handler to create a root span per request.
func otelMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !otelEnabled {
			next.ServeHTTP(w, r)
			return
		}
		ctx, span := startSpan(r.Context(), "agentarmor.request")
		span.SetAttr("http.method", r.Method)
		span.SetAttr("http.path", r.URL.Path)
		span.SetAttr("http.host", r.Host)
		span.SetAttr("net.peer.ip", r.RemoteAddr)
		if tid := r.Header.Get("X-Tenant-ID"); tid != "" {
			span.SetAttr("agentarmor.tenant_id", tid)
		}
		if span.TraceID != "" {
			w.Header().Set("X-Trace-ID", span.TraceID)
		}
		defer span.End()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RecordScan records the scanner pipeline result as a child span.
// Call immediately after scanPayload returns.
func RecordScan(ctx context.Context, action, rule, direction string) {
	if !otelEnabled {
		return
	}
	_, span := startSpan(ctx, "agentarmor.scan")
	span.SetAttr("agentarmor.action", action)
	span.SetAttr("agentarmor.rule", rule)
	span.SetAttr("agentarmor.direction", direction)
	span.End()
}

// ─── OTLP/HTTP batch sender ───────────────────────────────────────────────────

func otelBatchSender() {
	client := &http.Client{Timeout: 5 * time.Second}
	if otelInsecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}

	var batch []*otelSpan
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := sendOTLPBatch(client, batch); err != nil {
			log.Printf("⚠️  OTel flush: %v", err)
		}
		batch = batch[:0]
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case s := <-otelBatch:
			batch = append(batch, s)
			if len(batch) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// sendOTLPBatch serialises spans into OTLP/HTTP JSON and POSTs them.
// Trace/span IDs are hex strings; the OTLP JSON encoding requires them
// as base64-encoded bytes (proto3 JSON convention for bytes fields).
func sendOTLPBatch(client *http.Client, spans []*otelSpan) error {
	type attr struct {
		Key   string            `json:"key"`
		Value map[string]string `json:"value"`
	}
	type pbSpan struct {
		TraceID           string `json:"traceId"`
		SpanID            string `json:"spanId"`
		ParentSpanID      string `json:"parentSpanId,omitempty"`
		Name              string `json:"name"`
		Kind              int    `json:"kind"`
		StartTimeUnixNano string `json:"startTimeUnixNano"`
		EndTimeUnixNano   string `json:"endTimeUnixNano"`
		Attributes        []attr `json:"attributes"`
	}

	hexToB64 := func(h string) string {
		b, _ := hex.DecodeString(h)
		return base64.StdEncoding.EncodeToString(b)
	}

	pbSpans := make([]pbSpan, 0, len(spans))
	for _, s := range spans {
		s.mu.Lock()
		attrs := make([]attr, len(s.Attrs))
		for i, kv := range s.Attrs {
			attrs[i] = attr{Key: kv[0], Value: map[string]string{"stringValue": kv[1]}}
		}
		ps := pbSpan{
			TraceID:           hexToB64(s.TraceID),
			SpanID:            hexToB64(s.SpanID),
			Name:              s.Name,
			Kind:              2, // SPAN_KIND_SERVER
			StartTimeUnixNano: fmt.Sprintf("%d", s.StartNano),
			EndTimeUnixNano:   fmt.Sprintf("%d", s.EndNano),
			Attributes:        attrs,
		}
		if s.ParentID != "" {
			ps.ParentSpanID = hexToB64(s.ParentID)
			ps.Kind = 1 // SPAN_KIND_INTERNAL for child spans
		}
		s.mu.Unlock()
		pbSpans = append(pbSpans, ps)
	}

	payload := map[string]interface{}{
		"resourceSpans": []map[string]interface{}{{
			"resource": map[string]interface{}{
				"attributes": []attr{
					{Key: "service.name", Value: map[string]string{"stringValue": otelServiceName}},
				},
			},
			"scopeSpans": []map[string]interface{}{{
				"scope": map[string]string{"name": "agentarmor"},
				"spans": pbSpans,
			}},
		}},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := otelEndpoint
	if len(url) > 0 && url[len(url)-1] != '/' {
		url += "/"
	}
	url += "v1/traces"

	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

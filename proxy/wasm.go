package main

// WASM filter runtime — loads .wasm files from ./wasm-filters/ and runs them
// on every request payload, before forwarding to the LLM.
//
// Filters use the WASI stdio ABI (no custom host functions needed):
//   stdin  → JSON request context
//   stdout → JSON decision: {"action":"allow"} or {"action":"block","reason":"..."}
//
// Any language that compiles to WASI works: Rust, Go (GOOS=wasip1), C/Zig, AssemblyScript.
// See wasm-filters/README.md for the full ABI and example filters.
//
// Runtime: github.com/tetratelabs/wazero (pure Go, no CGO)

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// ─── types ───────────────────────────────────────────────────────────────────

type WASMFilter struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Enabled  bool      `json:"enabled"`
	LoadedAt time.Time `json:"loaded_at"`
	compiled wazero.CompiledModule
}

type wasmInput struct {
	Payload    string `json:"payload"`
	Direction  string `json:"direction"`
	SessionKey string `json:"session_key"`
	TenantID   string `json:"tenant_id"`
}

type wasmOutput struct {
	Action  string `json:"action"`  // "allow" | "block"
	Reason  string `json:"reason"`
}

// ─── globals ─────────────────────────────────────────────────────────────────

var (
	wasmRuntime wazero.Runtime
	wasmFilters []*WASMFilter
	wasmMu      sync.RWMutex
	wasmEnabled bool
)

const wasmFilterDir = "wasm-filters"

// ─── init ────────────────────────────────────────────────────────────────────

func initWASM() {
	entries, err := os.ReadDir(wasmFilterDir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("⚠️  wasm-filters dir: %v", err)
		}
		return
	}

	hasWasm := false
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".wasm" {
			hasWasm = true
			break
		}
	}
	if !hasWasm {
		return
	}

	ctx := context.Background()
	wasmRuntime = wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, wasmRuntime)

	reloadWASMFilters(ctx, entries)
	wasmEnabled = true
	log.Printf("🔌 WASM filter runtime ready (%d filters)", len(wasmFilters))
}

// reloadWASMFilters compiles all .wasm files in the filter directory.
func reloadWASMFilters(ctx context.Context, entries []os.DirEntry) {
	var loaded []*WASMFilter
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".wasm" {
			continue
		}
		path := filepath.Join(wasmFilterDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("⚠️  WASM read %s: %v", e.Name(), err)
			continue
		}
		compiled, err := wasmRuntime.CompileModule(ctx, data)
		if err != nil {
			log.Printf("⚠️  WASM compile %s: %v", e.Name(), err)
			continue
		}
		loaded = append(loaded, &WASMFilter{
			Name:     e.Name(),
			Path:     path,
			Enabled:  true,
			LoadedAt: time.Now(),
			compiled: compiled,
		})
		log.Printf("🔌 WASM filter loaded: %s", e.Name())
	}

	wasmMu.Lock()
	wasmFilters = loaded
	wasmMu.Unlock()
}

// ReloadWASM rescans the wasm-filters directory and recompiles changed modules.
// Called from the dashboard "Reload" action.
func ReloadWASM() error {
	if wasmRuntime == nil {
		initWASM()
		return nil
	}
	entries, err := os.ReadDir(wasmFilterDir)
	if err != nil {
		return err
	}
	reloadWASMFilters(context.Background(), entries)
	return nil
}

// ─── per-request execution ───────────────────────────────────────────────────

// runWASMFilters executes all enabled filters against the payload.
// Returns (blocked, ruleName). Fails open — any runtime error allows the request.
func runWASMFilters(payload, direction, sessionKey, tenantID string) (bool, string) {
	wasmMu.RLock()
	filters := append([]*WASMFilter{}, wasmFilters...)
	wasmMu.RUnlock()

	if len(filters) == 0 {
		return false, ""
	}

	inputJSON, _ := json.Marshal(wasmInput{
		Payload:    payload,
		Direction:  direction,
		SessionKey: sessionKey,
		TenantID:   tenantID,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	for _, f := range filters {
		if !f.Enabled {
			continue
		}

		var stdout bytes.Buffer
		mod, err := wasmRuntime.InstantiateModule(ctx, f.compiled,
			wazero.NewModuleConfig().
				WithStdin(bytes.NewReader(inputJSON)).
				WithStdout(&stdout).
				WithStderr(io.Discard).
				WithName(""), // allow multiple instances
		)
		if err != nil {
			log.Printf("⚠️  WASM %s run error: %v", f.Name, err)
			continue
		}
		mod.Close(ctx) //nolint:errcheck

		if stdout.Len() == 0 {
			continue
		}
		var out wasmOutput
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			log.Printf("⚠️  WASM %s bad output: %v", f.Name, err)
			continue
		}
		if out.Action == "block" {
			reason := out.Reason
			if reason == "" {
				reason = "blocked by WASM filter"
			}
			return true, "wasm:" + f.Name + " — " + reason
		}
	}

	return false, ""
}

// ─── dashboard helpers ────────────────────────────────────────────────────────

func ListWASMFilters() []WASMFilter {
	wasmMu.RLock()
	defer wasmMu.RUnlock()
	out := make([]WASMFilter, len(wasmFilters))
	for i, f := range wasmFilters {
		out[i] = WASMFilter{
			Name:     f.Name,
			Path:     f.Path,
			Enabled:  f.Enabled,
			LoadedAt: f.LoadedAt,
		}
	}
	return out
}

func ToggleWASMFilter(name string, enabled bool) {
	wasmMu.Lock()
	defer wasmMu.Unlock()
	for _, f := range wasmFilters {
		if f.Name == name {
			f.Enabled = enabled
			return
		}
	}
}

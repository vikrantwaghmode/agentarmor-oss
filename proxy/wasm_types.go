package main

import "time"

// wasmFilterDir is the directory WASM filters are read from. Untagged so the
// dashboard's filter-management handlers (file upload/delete) work in both
// flavors — only the wazero runtime itself is lite-stripped.
const wasmFilterDir = "wasm-filters"

// WASMFilterInfo is the wazero-free view of a loaded WASM filter, returned by
// ListWASMFilters() to the dashboard API. It lives in an untagged file so both
// the full (wazero-backed) and lite (stub) flavors share the same return type —
// the internal WASMFilter type carries a wazero.CompiledModule and therefore
// only exists in the full build.
type WASMFilterInfo struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Enabled  bool      `json:"enabled"`
	LoadedAt time.Time `json:"loaded_at"`
}

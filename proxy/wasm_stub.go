//go:build lite

package main

// Lite build flavor: the WASM filter runtime (github.com/tetratelabs/wazero) is
// compiled out. These no-op stubs satisfy the references main.go makes to the
// WASM subsystem so the core firewall builds without the wazero dependency.

var wasmEnabled = false

func initWASM() {}

func runWASMFilters(_, _, _, _ string) (bool, string) { return false, "" }

func ReloadWASM() error { return nil }

func ListWASMFilters() []WASMFilterInfo { return nil }

func ToggleWASMFilter(_ string, _ bool) {}

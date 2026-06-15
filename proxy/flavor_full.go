//go:build !lite

package main

// buildFlavor identifies the compiled feature set. The full flavor (default)
// includes the compliance engine and the WASM filter runtime.
const buildFlavor = "full"

//go:build lite

package main

// buildFlavor identifies the compiled feature set. The lite flavor compiles out
// the compliance engine (blake3 + fpdf) and the WASM filter runtime (wazero)
// for a smaller binary and reduced attack surface.
const buildFlavor = "lite"

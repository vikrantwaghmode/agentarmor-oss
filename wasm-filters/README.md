# AgentArmor WASM Filters

Drop `.wasm` files here — AgentArmor loads and runs them on every request without rebuilding the proxy.

## ABI

Filters use **WASI stdio** — read JSON from stdin, write JSON to stdout. No custom host functions; any language that compiles to `wasip1` works.

### Input (stdin)
```json
{
  "payload":     "the full request text (all non-system messages joined)",
  "direction":   "Request" | "Response",
  "session_key": "bearer:abc123",
  "tenant_id":   "default"
}
```

### Output (stdout)
```json
{ "action": "allow" }
```
or
```json
{ "action": "block", "reason": "matched competitor domain" }
```

Any stdout that isn't valid JSON is ignored and the request is allowed.

---

## Writing a filter in Go (compiled to WASI)

```go
//go:build wasip1
// +build wasip1

package main

import (
    "encoding/json"
    "os"
    "strings"
)

type Input struct {
    Payload   string `json:"payload"`
    Direction string `json:"direction"`
}

func main() {
    var in Input
    json.NewDecoder(os.Stdin).Decode(&in)

    if strings.Contains(strings.ToLower(in.Payload), "competitor-name") {
        json.NewEncoder(os.Stdout).Encode(map[string]string{
            "action": "block",
            "reason": "competitor domain mentioned",
        })
        return
    }
    json.NewEncoder(os.Stdout).Encode(map[string]string{"action": "allow"})
}
```

Compile:
```bash
GOOS=wasip1 GOARCH=wasm go build -o wasm-filters/competitor-block.wasm ./filter.go
```

---

## Writing a filter in Rust

```rust
use std::io::{self, Read, Write};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Input { payload: String }

#[derive(Serialize)]
struct Output { action: &'static str, reason: &'static str }

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let inp: Input = serde_json::from_str(&input).unwrap_or(Input { payload: String::new() });

    let out = if inp.payload.contains("DROP TABLE") {
        Output { action: "block", reason: "SQLi pattern detected" }
    } else {
        Output { action: "allow", reason: "" }
    };
    io::stdout().write_all(serde_json::to_vec(&out).unwrap().as_slice()).unwrap();
}
```

Compile:
```bash
cargo build --target wasm32-wasip1 --release
cp target/wasm32-wasip1/release/my_filter.wasm ../wasm-filters/
```

---

## Managing filters from the dashboard

**Infrastructure tab (10) → WASM Filters section:**
- Lists all loaded filters with load time and enabled/disabled toggle
- **Reload** button rescans the directory and recompiles changed files
- Filters take effect immediately — no proxy restart needed

---

## Timeout

Each filter has a **500 ms** execution budget per request. Filters that exceed this are skipped (fail-open). Keep filters fast — use simple string matching, not heavy regex.

## Ordering

Filters run in filesystem order (alphabetical). The first filter that returns `"block"` wins; remaining filters are skipped.

# BoundaryAI — Go SDK

Go client for the **BoundaryAI** universal AI firewall — deterministic action-level enforcement for AI agents, LLM tool calls, and system commands.

Patent Pending US #64/029,125

## Install

```bash
go get github.com/skvcool-rgb/Boundaryai-go@v0.6.0
```

## Usage

```go
package main

import (
    "log"
    boundaryai "github.com/skvcool-rgb/Boundaryai-go"
)

func main() {
    client := boundaryai.NewClient("bai_xxx", "https://boundaryai-engine-248951128296.us-east1.run.app")

    decision, err := client.Evaluate(boundaryai.Action{
        Type:  "system.command",
        Scope: "rm -rf /data",
    })
    if err != nil {
        log.Fatal(err)
    }
    if decision.Blocked {
        log.Fatalf("Action blocked: %s", decision.Reason)
    }
}
```

## Features

- Context-aware `Evaluate` + `EvaluateBatch`
- Retry with exponential backoff (max 3 retries, 100ms base delay)
- Fail-open / fail-closed modes
- Built-in `ScanPII` — 7 pattern classes: SSN, credit cards (Luhn), AWS keys, OpenAI/Anthropic keys, GitHub PATs, passwords
- `Health()` for liveness checks
- Version constant: `boundaryai.Version`

## Sister SDKs

| Language | Registry | Install |
|---|---|---|
| Python | [PyPI](https://pypi.org/project/boundaryai/0.6.0/) | `pip install boundaryai==0.6.0` |
| Node | [npm](https://www.npmjs.com/package/boundaryai/v/0.6.0) | `npm install boundaryai@0.6.0` |
| Rust | [crates.io](https://crates.io/crates/boundaryai/0.6.0) | `cargo add boundaryai@0.6.0` |
| Go | this repo | `go get github.com/skvcool-rgb/Boundaryai-go@v0.6.0` |

## Tests

```bash
go test -v ./...
```

22 tests pass (15 unit + 7 `ScanPII` subtests).

## Engine

All SDKs hit the same deterministic Rust enforcement engine on Cloud Run (rev `00049-skx`, v0.6.0, 42 policies, 28 watchlist terms, HMAC-SHA256 audit chain, Ed25519 agent identity).

## License

MIT

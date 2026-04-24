# BoundaryAI Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/skvcool-rgb/Boundaryai-go.svg)](https://pkg.go.dev/github.com/skvcool-rgb/Boundaryai-go)

Universal AI Firewall SDK for Go — drop-in middleware that prevents PII,
credentials, and sensitive data from leaking through any AI tool call.

**Current version: v0.7.20** (synced with engine + Python/Rust/Node SDKs on 2026-04-23)

---

## Install

```bash
go get github.com/skvcool-rgb/Boundaryai-go
```

> **Module path — future migration (tracked):** this SDK currently
> publishes at `github.com/skvcool-rgb/Boundaryai-go` (the path you install
> from above). An org-level rename to `github.com/boundaryai/go-sdk` is
> planned for a future release — enterprise buyers flag personal-account
> paths as a supply-chain signal. When the rename happens, the old path
> will continue to redirect for at least 6 months so existing builds don't
> break, and release notes will call out the new import path explicitly.
> For now (v0.7.20), no import change is needed.
>
> No action required for current integrators.

---

## Quick start

```go
package main

import (
    "context"
    "log"

    "github.com/skvcool-rgb/Boundaryai-go"
)

func main() {
    client, err := boundaryai.New(boundaryai.Config{
        APIKey:    "bai_...",
        EngineURL: "https://boundaryai-engine-248951128296.us-east1.run.app",
    })
    if err != nil {
        log.Fatal(err)
    }
    decision, err := client.Evaluate(context.Background(), boundaryai.Action{
        AgentID:     "my-agent",
        Type:        "file.delete",
        Description: "delete /tmp/foo",
    })
    if err != nil {
        log.Fatal(err)
    }
    if decision.Block {
        log.Fatalf("blocked: %s", decision.Reason)
    }
}
```

---

## Documentation

- Full Go API: https://pkg.go.dev/github.com/skvcool-rgb/Boundaryai-go
- Python SDK: https://pypi.org/project/boundaryai/
- Rust SDK: https://crates.io/crates/boundaryai
- Node SDK: https://www.npmjs.com/package/boundaryai
- Dashboard Integrations tab: https://dashboard.boundaryai.com/dashboard?tab=integrations

## License

MIT.

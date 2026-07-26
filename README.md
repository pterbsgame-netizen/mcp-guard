# mcp-guard

A single static binary that sits between an MCP client and an MCP stdio server,
records everything, and — eventually — enforces a policy on what tools are
allowed to *do*.

**Status: stage 0.** Right now it is a tap, not a guard. It relays bytes and
writes a session log. It blocks nothing, inspects nothing, rewrites nothing.

## Why another one

`mcp-scan` (Invariant Labs / Snyk) and the Lasso MCP Gateway already exist. The
bet here is on three differences:

1. **One static binary, zero runtime dependencies, zero network calls.** The
   artifact is a line in someone else's `mcp.json`. Download a file, point at
   it, done — no pip, no venv, no interpreter version, no API key, no cloud
   guardrail endpoint. Detection is fully offline and deterministic.
2. **It never edits your config.** You wire it in by hand, once. Nothing
   injects itself into server configs at startup and unwinds on exit, so there
   is no window where a crash leaves a mangled `mcp.json` behind.
3. **Effects, not content.** The core is a policy over tool calls — what got
   written, what got executed, where the data came from — not a classifier
   trying to decide whether a string is "an instruction". Content inspection
   only ever raises a taint level; it never blocks on its own.

> The detailed comparison table goes here, after actually reading the `mcp-scan`
> proxy source. Claims above are the design intent, not a verified benchmark.

## Design rule

> Do not classify content. Control effects.

CurXecute is not stopped by recognising an instruction inside a Slack message.
It is stopped by refusing the write to `~/.cursor/mcp.json`. That is
deterministic, testable, has a measurable false-positive rate, and does not fall
over when the attacker rephrases.

## Build

```bash
go build -o dist/mcp-guard.exe ./cmd/mcp-guard
```

```bash
go test ./...
```

The race detector is worth running — the proxy has three goroutines and one of
them deliberately outlives `Run`. On Windows `-race` needs cgo and a C compiler,
which is not on `PATH` by default after an MSYS2 install:

```bash
PATH="/c/msys64/ucrt64/bin:$PATH" CGO_ENABLED=1 go test -race ./...
```

## Use

```bash
mcp-guard --log ~/.mcp-guard/session.jsonl -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\tmp
```

Everything after `--` is the real server command. `mcp-guard` starts it, relays
stdin/stdout/stderr unchanged, and appends one JSON object per message to the
log.

The log is rotated once it passes `--log-max-bytes` (64 MiB by default, `0`
disables it): the current file is renamed with a UTC stamp and a fresh one is
started. Nothing is deleted — the corpus is the point — so old segments are
yours to prune. It adds up faster than it looks: a single `tools/list` response
from a real server runs to ~15 KB, and the client repeats the handshake on every
restart, so the log grows even on days when no tool is ever called.

### Wiring into a client

Replace the server's own command with `mcp-guard` plus the original command.
Claude Desktop, `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "C:\\Users\\me\\dev\\mcp-guard\\dist\\mcp-guard.exe",
      "args": [
        "--log", "C:\\Users\\me\\.mcp-guard\\session.jsonl",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\me\\tmp"
      ]
    }
  }
}
```

Restart the client. If everything is right, nothing changes: the same tools
appear, the same calls work, the same errors show up — and the session lands in
the log.

## The session log is sensitive

`session.jsonl` contains the verbatim content of every tool call and every tool
result: file contents, API responses, and any credential the agent happened to
read along the way. It is in `.gitignore`. Treat it like a password file, and do
not paste it into an issue.

**On Windows the log is not yet protected by file permissions.** It is opened
with mode `0600`, but Go's permission bits are almost entirely ignored on
Windows: the file simply inherits the parent directory's ACL. Verified on a real
session — the resulting ACL was `SYSTEM`, `Administrators` and the owning user,
all `FullControl`. Restricting it properly needs an explicit security descriptor
via `golang.org/x/sys/windows`, which is a stage-1 task. Until then, put the log
somewhere already protected and do not assume the mode argument did anything.

## Roadmap

| Stage | What | State |
|---|---|---|
| 0 | Transparent pipe + session log | **done** |
| 1 | JSON-RPC parsing, request/response correlation, session model, `replay` | next |
| 2 | Tool pinning: `approve` → `mcp-guard.lock`, canonicalised schema hashes | |
| 3 | Effect policy + taint propagation ← the actual product | |
| 4 | Content normalisation, advisory signals, an `eval` metrics harness | |

Default mode on install will be **observe**, never enforce. A tool that breaks
someone's workflow on day one gets uninstalled on day one.

## Notes on Windows

Development happens on Windows, which the design has to account for rather than
defer:

- There is no `SIGTERM`. Closing the server's stdin is the only polite shutdown
  signal available, so the shutdown ladder has one rung fewer than on Unix. See
  `internal/proxy/terminate_windows.go`.
- Path canonicalisation for stage 3 has a materially different threat surface
  here: case-insensitive comparison, `8.3` short names, ADS (`file.txt:evil`),
  UNC and `\\?\` prefixes, junctions in addition to symlinks. That work is
  bigger on Windows than on Unix, not smaller.

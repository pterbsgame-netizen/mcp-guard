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
which an MSYS2 install does not put on `PATH`. In PowerShell:

```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"; $env:CGO_ENABLED = "1"; go test -race ./...
```

The equivalent on Linux or macOS, where the toolchain is already there:

```sh
go test -race ./...
```

## Use

```bash
mcp-guard -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\tmp
```

Everything after `--` is the real server command. `mcp-guard` starts it, relays
stdin/stdout/stderr unchanged, and writes one JSON object per message to a log.

Each run gets its own file under `--log-dir` (`~/.mcp-guard/sessions` by
default), named so the directory sorts chronologically. That is not tidiness: a
client runs one proxy per configured server, so several are alive at once, and
pointing them all at one file interleaves their sessions and turns rotation into
a race between processes renaming the same file. `--log` writes to a single file
instead, and is only safe with one proxy running.

Logs are rotated past `--log-max-bytes` (64 MiB by default, `0` disables it).
Nothing is ever deleted — the corpus is the point — so old segments are yours to
prune. It adds up faster than it looks: one `tools/list` response from a real
server runs to ~15 KB, and the client repeats the handshake on every restart, so
the corpus grows even on days when no tool is ever called.

### Pinning what a server advertises

```bash
mcp-guard approve -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\dev
```

This starts the server, asks what tools it has, and writes `mcp-guard.lock`
recording each tool's name, description and input schema. Commit that file: a
tool that later rewrites its description or widens its schema then shows up in a
diff during review, which is where it should be caught.

```bash
mcp-guard approve --diff -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\dev
```

reports what changed and exits non-zero if anything did, so it can gate a build.

To have the proxy check as it runs, point it at the lock:

```bash
mcp-guard --lock mcp-guard.lock -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\dev
```

By default a mismatch is recorded and the call goes through. `--enforce` refuses
calls to tools that changed, answering the client with the reason instead of the
result. Run in the default mode for a week first: a tool that breaks a workflow
the day it is installed is uninstalled the day it is installed.

**What pinning does not do.** `tools/list` is never blocked — refusing it leaves
the client with no tools and a broken server — so a rewritten description does
reach the model before any call is refused. Pinning catches the change and stops
the effect; it does not stop the text from being read. Controlling effects is
stage 3's job.

### Reading a session back

```bash
mcp-guard replay
```

With no argument it replays every log in the default directory; give it a file
or a directory to replay that instead. Output is a transcript: direction, method
names, which reply answered which request and how long it took, the tool each
`tools/call` targeted, and a per-run summary of the negotiated protocol version,
the advertised tools and the calls that failed. It is offline and deterministic
— no server is started and nothing is contacted, so the same log always produces
the same transcript.

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

Permissions are restricted to the owning user. On Unix that is just the `0600`
the file is created with. On Windows the mode argument is very nearly a no-op —
it maps only to the read-only attribute, and the file otherwise inherits the
directory ACL, which on a stock profile hands `SYSTEM` and `Administrators` full
control — so the DACL is set explicitly instead: protected, inheritance severed,
one allow-all entry for the owning user. This is the only reason the project
depends on anything outside the standard library.

If that fails, `mcp-guard` says so on stderr and keeps going rather than taking
the client's server down with it.

## Roadmap

| Stage | What | State |
|---|---|---|
| 0 | Transparent pipe + session log | **done** |
| 1 | JSON-RPC parsing, request/response correlation, session model, `replay` | **done** |
| 2 | Tool pinning: `approve` → `mcp-guard.lock`, canonicalised schema hashes | **done** |
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

# Working on mcp-guard

A security proxy for MCP stdio servers, in Go. The client launches `mcp-guard`,
`mcp-guard` launches the real server, and everything between them is relayed,
recorded, and — depending on the level — refused.

Read `README.md` for what it does. Read `git log` before changing anything: the
commit messages carry the reasoning, including what was tried and rejected, and
there is more of it there than in this file.

## The rule everything follows

> Control effects, not content.

In MCP an instruction and data are the same bytes, so "is this text a command"
is not answerable. "Is this call about to write to `~/.ssh`" is a fact. Policy
decides on effects. Content signatures may only raise the taint level — they
never block, and no change should make them able to. The rules live in a public
repo; evasion is cheap and false positives are daily.

The metric that decides whether this survives is **blocks per week of ordinary
use**, target under one. Anything that raises it needs to justify itself.

## Where things are

| | |
|---|---|
| Design plan | `docs/PLAN.md` — the original brief, still the source of truth for scope |
| Enforcement plan | `docs/plan-enforcement.md` |
| Session logs | `%USERPROFILE%\.mcp-guard\sessions\` (one file per proxy run) |
| Client config | `%APPDATA%\Claude\claude_desktop_config.json` |

## Current state, as of 30 July 2026

Stages 0–4 of the plan are done. CI is green on Windows and Linux. `ROADMAP.md`
tracks every item; check it before assuming something is finished.

- Running at **`enforce`** on the development machine, wrapping four servers:
  `filesystem` and `fetch` from `claude_desktop_config.json`, `context7` and
  `blender` from `~/.claude.json`.
- It was switched on only after the number said so: **28 tool calls of ordinary
  work over two days, zero blocks.** Deliberate probes are excluded from that
  count via `corpus/excluded-sessions.txt`, and including them gives 11.1 blocks
  per week — four correct refusals of attacks, which is the measurement working
  rather than friction to be tuned away.
- **`strict` is not usable here**, and not because of a bad rule. It refuses
  `confirm` as well, and `execute_blender_code` is exec class, so a Blender
  workflow alone produces around 30 refusals a week. That does not improve with
  more data; it improves when a confirm can be answered instead of refused.
- The corpus only grows through a wrapped MCP server. Built-in file tools bypass
  the proxy entirely, so a day of heavy editing can leave it at zero.
  `mcp-guard eval --benign` prints the call count beside the rate for exactly
  that reason — a zero over two calls is not a rate.

## Build and test

```powershell
go build -o dist\mcp-guard.exe ./cmd/mcp-guard
go test ./...
```

The race detector needs cgo and a C compiler, which an MSYS2 install does not
put on `PATH`:

```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"; $env:CGO_ENABLED = "1"; go test -race ./...
```

Run `go vet ./...` and `gofmt` before committing. CI runs both platforms and
runs `-race` on Linux only, which is where the Unix build tags get compiled at
all — `terminate_unix.go` and `secure_unix.go` are never built here.

## Conventions

- Code, comments and commit messages in **English**. The repository is meant to
  be public eventually.
- **No new dependencies** without a stated reason. Current set is
  `golang.org/x/sys` (Windows ACLs on the log), `fsnotify` (config watching) and
  `yaml.v3` (policy files). Each was argued for in its commit.
- Comments explain **why**, not what. Several encode a defect that was fixed
  once and must not come back; deleting them deletes the reason.
- Commit messages are prose, and long. State what was found, not only what was
  changed. Defects discovered while building something are worth a paragraph.

## Traps in this environment

Every one of these cost real time. They will happen again.

- **Do not rewrite Go files with PowerShell** (`Set-Content`, regex replaces on
  whole files). It mangles UTF-8 in comments into mojibake, and it has happened
  four times. Use the editing tools, or `sed` through Bash.
- **`git commit -m` with a PowerShell here-string breaks** when the message
  contains quotes. Write the message to a file and use `git commit -F`.
- **`Get-ChildItem` reports 0 bytes for an open session log.** NTFS updates the
  directory entry lazily and the proxy holds the file open. Read the content, or
  use `mcp-guard replay`, before concluding a log is empty.
- **PowerShell 5.1 has no ternary operator** and no `&&`/`||` chaining.
- Writing a Go string literal containing a raw tab or newline through the Write
  tool has produced NUL bytes in the file. Use escape sequences.

## Things deliberately not done

Do not add these without a conversation. Each is a decision, not an oversight.

- Web panel, dashboard, multi-tenancy, telemetry, cloud anything.
- A plugin or scripting engine for rules. Rules are data.
- Local ML models or embeddings.
- Silent sanitisation of content. Blocking with a clear message is honest;
  quietly editing a tool result breaks the agent invisibly.
- HTTP/SSE transport, child-process sandboxing, an LLM classifier. These are
  stage 5, explicitly deferred until there are real users.
- Unicode NFC/NFD path normalisation — a known, documented gap in
  `internal/fspath`, left out to avoid depending on `golang.org/x/text`.

## Known limits worth restating

- `tools/list` is never blocked, so a poisoned tool description still reaches
  the model; pinning stops the effect, not the reading.
- `confirm` cannot ask. `elicitation/create` needs client support that the
  handshake log shows is absent, so at `strict` a confirm is refused instead.
- Only stdio. A server added over HTTP is unguarded, silently.
- A stdio proxy cannot see what a server process does on its own network
  connections. A server with built-in telemetry exfiltrates without a single
  byte crossing this proxy. That needs sandboxing, which is stage 5.
- **Taint does not cross servers.** One proxy process per server means one
  session each, and taint lives in that session. The agent fetches a page
  through `fetch` — tainting *that* proxy — and then runs code through
  `blender`, a different process with a clean session. Observed on real
  traffic: five `execute_blender_code` verdicts, every one `tainted=false`,
  while the fetch sessions beside them were tainted.

  The threat model is cross-server by nature: read untrusted content with one
  tool, act with another. So `exec.action_if_tainted` never fires in a real
  multi-server setup, and the escalation only worked in tests because tests put
  everything in one session. Sharing taint means shared state between processes
  — grouping by parent pid would identify proxies belonging to one client — and
  that is a deliberate design change, not a patch. It will also raise the block
  rate, so it should not land before enforcement has a track record.

## Emergency

```
MCPGUARD_OFF=1
```

in the client's environment relays with no checks at all. It is read before any
config file is opened, so a broken policy cannot cost the user their tools.

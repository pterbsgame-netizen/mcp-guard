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

### How this compares, as of July 2026

`mcp-scan` is now **Snyk Agent Scan** (`snyk-agent-scan`). Reading its README
changed the picture rather than confirming it, so the differences worth naming
are not the ones assumed at the start:

| | Snyk Agent Scan | mcp-guard |
|---|---|---|
| shape | scanner and inventory | runtime proxy |
| when it acts | before or between sessions | on every message |
| account required | Snyk sign-up plus `SNYK_TOKEN` | none |
| network | reports to Snyk Evo in background mode | never |
| breadth | 13 agents, MCP servers **and** skills, 15+ issue codes | one transport, three threat classes |
| enforcement | reports | refuses the call |

The overlap is smaller than it looks. Agent Scan answers "what is installed and
does any of it look dangerous"; that is inventory across a fleet, and it does it
across far more surface than this ever will. mcp-guard answers "this specific
call is about to write to `~/.ssh` — no", which is a different question asked at
a different moment.

Two things are worth knowing before choosing:

- **Scanning a config executes it.** To read tool descriptions, Agent Scan
  starts the stdio servers listed in the config; it asks for consent per server
  and recommends a sandbox for untrusted configs. mcp-guard's `approve` starts a
  server too, but only the one named on its command line, never a config's worth.
- **The cloud dependency is now mandatory, not optional.** A token is required
  before any scan. Being able to run with no account and no network was a guess
  when this project started; it is now the clearer difference.

Scope note: this is from the README, not from running it — the tool needs a Snyk
account this machine does not have. What it does at runtime, and whether the
proxy mode the older `mcp-scan` shipped still exists, is not something reading
documentation can settle.

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

### Controlling what calls are allowed to do

```bash
mcp-guard --policy default -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\dev
```

The policy decides on **effects**, never on wording. CurXecute is not stopped by
noticing an instruction inside a message; it is stopped because a call tried to
write to the file that decides which servers run. That is a fact about the call,
it is testable, its false positives are countable, and rephrasing does not get
around it.

Paths are resolved before they are matched, so there is no spelling that walks
past a rule: `~`, `%USERPROFILE%`, `$HOME`, `..` segments, symlinks, letter case,
Windows 8.3 short names, `\\?\` prefixes and NTFS alternate data streams all
reduce to one form first.

Rules are data, in three pattern forms and no more:

```yaml
paths:
  deny:    ["~/.ssh/**", "**/.env", "**/mcp.json"]
  confirm: ["**/package.json"]
  confirm_if_tainted: ["**/*.sh"]
```

`~/.ssh/**` is a subtree, `~/.bashrc` is one file, `**/.env` is that name
anywhere. Write your own with `--policy path/to/rules.yaml`; the built-in set is
`internal/policy/default.yaml`.

**Taint.** A result from a tool that brings in content nobody vouches for —
fetched pages, mail, issues — marks the session. Which tools those are is a
list of name patterns in the policy; the official fetch server's only tool is
called `fetch`, and a test pins that it and the other common spellings are
actually recognised, because a taint source nobody matches is a stage that
never runs. Nothing is blocked for that
reason alone; it tightens what the rules already say, so a write that is
ordinary during honest work becomes something to confirm afterwards. The
decision is about where the content came from, not what it says, which is why
rewording does not defeat it.

### Three levels

| level | `deny` | `confirm` |
|---|---|---|
| `observe` (default) | recorded | recorded |
| `enforce` | **refused** | recorded, announced on stderr, relayed |
| `strict` | **refused** | **refused** |

```bash
mcp-guard -enforce -- npx ...
```

`-enforce=strict` refuses confirms too; `-enforce=off` goes back to observing.

The two lists are not the same kind of thing, which is why they are not
enforced together. `deny` covers credentials, agent configuration and shell
startup files — places honest work never writes. `confirm` covers
`package.json`, Makefiles and shell scripts, which it writes all day. A guard
that refuses the second kind on the day it is switched on is switched off the
same day, and then it guards nothing at all.

`mode:` in the policy file takes the same three values. **The flag wins when
both are set**, in either direction: a policy file is meant to be committed and
may belong to somebody else, while whoever is unbreaking this at nine in the
morning owns the client config.

Pin mismatches are their own case. A tool that *changed* since you approved it
is refused whenever enforcing — it is rare, precise, and the refusal names the
cure. A tool list that could not be checked at all is only held at `strict`:
"we do not know" is a far weaker claim than "it changed", and under enforcement
its blast radius would be the whole server dying over one malformed schema.

**What `confirm` does at `strict`.** It refuses, with an explanation. The
protocol has `elicitation/create` for asking the user, but no client seen so far
declares it — mcp-guard now records what each side declared during the
handshake, so that claim can be checked against the logs instead of assumed.
Until one does, there is no way to ask from inside a stdio proxy, and refusing
while saying so beats pretending to have asked.

### If it goes wrong

```bash
MCPGUARD_OFF=1
```

Set that in the client's environment and mcp-guard relays with no checks at
all: no pin check, no policy, no content scan. It is read before any
configuration file is opened, so a typo in a policy — otherwise a refusal to
start, and therefore an MCP server that simply never appears in the client —
cannot cost you your tools. Only affirmative values count, so `MCPGUARD_OFF=0`
does not disarm the guard.

The session log keeps being written and records `from: "off"`, so an
unprotected session is identifiable afterwards rather than silently
indistinguishable from a guarded one.

### Content signals, which never block

With a policy in place, tool results are scanned for instruction-shaped content.
A match does **not** block anything and cannot: it raises the session's taint
level, which makes the effect rules stricter. That is the whole contract.

The reason is not modesty about regular expressions. The rules are in a public
repository, so getting around them takes an attacker about thirty seconds, while
the false positives land on the user every day — a blog post about prompt
injection, a code review of a file containing the phrase. As a defence the value
is near zero; as telemetry, and as a reason to be stricter about effects
afterwards, it is real. It is kept in exactly that role.

Before matching, text is unfolded so a signature written in plain English still
finds a disguised instruction: base64, hex, percent-encoding, HTML comments and
`display:none` blocks are decoded, and zero-width characters, Cyrillic
lookalikes, fullwidth forms and bidirectional overrides are folded away. An
instruction found only after decoding scores higher than one in plain view,
because prose does not accidentally hide itself.

Signatures are deliberately weak: no single phrase reaches the threshold alone,
because install docs pipe scripts into shells and this project's own README
talks about refusing writes to `mcp.json`. Missing a taint is not missing an
attack — the effect rules refuse the write to `mcp.json` on their own, whatever
the surrounding text says.

### Measuring it

```bash
mcp-guard eval --attack corpus/attack --benign ~/.mcp-guard/sessions
```

Recall on the attack corpus is the easy number and is currently 100% over six
published shapes — but every rule was written after reading them, so it proves
the rules match their own examples, not that they generalise. The number that
decides whether the tool survives is the false-positive rate on real traffic,
which cannot be manufactured. The benign side reports how much evidence it
actually had, so a rate measured over four calls is not mistaken for a rate, and
the headline "blocks per week" refuses to compute from less than an hour of
elapsed time.

### Guarding the config itself

The proxy is a line in the config it would be guarding. Anyone who can rewrite
that file removes the proxy from the chain first, and everything downstream
becomes theatre. So this part lives outside the traffic path:

```bash
mcp-guard verify --write
```

records the MCP server declarations found in the known client configs.

```bash
mcp-guard verify
```

checks them and exits non-zero if anything changed.

```bash
mcp-guard watch
```

does the same continuously, reporting as it happens.

Only the server declarations are recorded, never whole files. Clients keep
caches, feature flags and window positions in the same files and rewrite them
constantly; a whole-file hash would fire every few minutes and be ignored within
a day. Environment variable and header *names* are covered — a credential
reaching a server it did not use to reach is exactly the thing to catch — and
their values never are, because this file belongs in a repository.

Keep the baseline in a repository rather than beside the configs it guards: one
stored next to what it protects is editable by whoever edits that.

Which repository matters, though, and the two cases are not the same. A baseline
scoped to a **project** covers that project's `.cursor/mcp.json` and belongs in
it, where a change shows up in review like any other. One scoped to a **machine**
covers `%APPDATA%\Claude` and `~/.claude.json`, and records its owner's
directory layout and the list of servers they run — worth keeping under version
control somewhere private, and worth thinking about before it goes anywhere
public. This repository ignores both, because anything generated here is the
second kind.

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
| 2 | Tool pinning, plus `verify`/`watch` over client configs | **done** |
| 3 | Effect policy + taint propagation ← the actual product | **done** |
| 4 | Content normalisation, advisory signals, an `eval` metrics harness | **done** |

Default mode on install is **observe**, never enforce. A tool that breaks
someone's workflow on day one gets uninstalled on day one.

### What is not proven yet

The false-positive rate, and it is worth being precise about why.

The attack side is covered by tests — CurXecute is refused at the write, a
silently swapped tool description is caught, a rewritten config is reported.
Taint has now fired end to end against the real fetch server, so the escalation
is not just tested in isolation.

"Ordinary work never trips" is the claim with no evidence behind it. It can only
be measured against real sessions, and a corpus is only as good as the surface
it covers: one filesystem server scoped to a single project directory exercises
a handful of rules and none of the rest. A zero measured there means "little was
attempted", not "the rules are good", and reporting it as a false-positive rate
would be dressing up an absence of data.

```bash
mcp-guard eval --benign ~/.mcp-guard/sessions
```

reports how many calls it actually judged alongside the rate, so the two are
never confused. Until that count is large and varied, treat enforcement as
untested on real traffic.

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

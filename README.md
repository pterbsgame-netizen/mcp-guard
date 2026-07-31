# mcp-guard

[![CI](https://github.com/pterbsgame-netizen/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/pterbsgame-netizen/mcp-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**[pterbsgame-netizen.github.io/mcp-guard](https://pterbsgame-netizen.github.io/mcp-guard/)** — the same thing with pictures ([по-русски](https://pterbsgame-netizen.github.io/mcp-guard/ru.html))

A security proxy for MCP stdio servers. Your client launches `mcp-guard`,
`mcp-guard` launches the real server, and everything between them is relayed,
recorded, and — depending on the level — refused.

One static binary. No account, no network calls, no runtime to install.

```
Claude Desktop ──stdio── mcp-guard ──stdio── npx server-filesystem
                             │
                             └── session log, policy, tool pinning
```

## The problem

An MCP server can read your files and run your code. Nothing checks what it
does with that, and three things go wrong in practice:

- A server changes a tool's description after you approved it, and the new one
  tells your agent to read `~/.ssh/id_rsa` first.
- Content the agent fetched — a web page, an issue, an email — contains text
  the model treats as instruction.
- Someone edits the config that decides which servers run at all.

## The rule this follows

> **Control effects, not content.**

In MCP an instruction and data are the same bytes, so "is this text a command"
has no answer. "Is this call about to write to `~/.ssh`" is a fact. Policy
decides on effects. Content signatures may only raise a suspicion level — they
never block, by construction.

The metric that decides whether a tool like this survives is **blocks per week
of ordinary use**. Target: under one.

## Install

Download a binary from [releases](https://github.com/pterbsgame-netizen/mcp-guard/releases),
or:

```bash
go install github.com/pterbsgame-netizen/mcp-guard/cmd/mcp-guard@latest
```

Then put it in front of the servers you already run:

```bash
mcp-guard install --dry-run
```

That finds the client configs on this machine, prints what it would change, and
writes nothing. Drop `--dry-run` to apply it. Every file is copied aside first,
and `mcp-guard uninstall` puts the original commands back — it reads them out of
the wrapped ones, so it does not need the backup to work.

Only the declarations it actually changes are rewritten, spliced back into the
original bytes. Whatever else lives in those files — caches, window positions,
keys it has never heard of — comes out identical.

By hand it is the same edit: replace the server command with `mcp-guard`, then
`--`, then the command you had before.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "C:\\path\\to\\mcp-guard.exe",
      "args": [
        "--policy", "default", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\me\\dev"
      ]
    }
  }
}
```

Restart the client. If it worked, nothing changed: same tools, same calls, same
errors — and a session log appears under `~/.mcp-guard/sessions`.

**Start in observe mode**, which is the default. It records what it would have
refused and refuses nothing. Live with it for a week, read the numbers, then
switch enforcement on.

## What it does

### Pins what a server advertises

```bash
mcp-guard approve -- npx -y @modelcontextprotocol/server-filesystem ~/dev
```

Writes `mcp-guard.lock` with each tool's name, description and input schema.
Commit it: a tool that later rewrites its description or widens its schema shows
up in a diff during review.

Schemas are canonicalised (RFC 8785) before hashing, so a server that
re-serialises its output between runs is not mistaken for one that changed it —
which is the difference between a useful check and one you turn off on day two.

`mcp-guard approve --diff` reports changes and exits non-zero, so it can gate a
build.

### Decides what a call may do

```bash
mcp-guard --policy default -enforce -- npx -y ... 
```

Paths are resolved **before** they are matched, so there is no spelling that
walks past a rule: `~`, environment variables, `..` segments, symlinks, letter
case, Windows 8.3 short names, `\\?\` prefixes and NTFS alternate data streams
all reduce to one form first.

Rules are data, in three pattern forms and no more:

```yaml
paths:
  deny:    ["~/.ssh/**", "**/.env", "**/mcp.json"]
  confirm: ["**/package.json"]
  confirm_if_tainted: ["**/*.sh"]
```

`~/.ssh/**` is a subtree, `~/.bashrc` is one file, `**/.env` is that name
anywhere. Write your own with `--policy path/to/rules.yaml`.

Candidate paths are pulled from anywhere in a call's arguments, not from a
parameter named `path` — otherwise every server would need its own special case,
and an unfamiliar one would be covered by nothing.

### Tracks where content came from

A result from a tool that brings in content nobody vouches for — fetched pages,
mail, issues — marks the session. Nothing is blocked for that alone; it tightens
what the rules already say, so a write that is ordinary during honest work
becomes something to confirm afterwards.

The decision is about the source, not the wording, which is why rephrasing does
not defeat it.

### Scores content, and never blocks on it

Tool results are scanned for instruction-shaped text. Before matching, the text
is unfolded: base64, hex, percent-encoding, HTML comments and `display:none`
blocks are decoded, and zero-width characters, Cyrillic lookalikes, fullwidth
forms and bidirectional overrides are folded away.

A match **cannot** block. It raises the taint level and nothing else. The rules
are in a public repository, so evading them takes about thirty seconds, while
the false positives land on the user every day. As a defence the value is near
zero; as a reason to be stricter about effects afterwards it is real.

### Guards the config itself

```bash
mcp-guard verify --write   # record
mcp-guard verify           # check, non-zero if changed
mcp-guard watch            # keep watching
```

This lives outside the traffic path deliberately: the proxy is a line in the
file it would be guarding, so anyone who can rewrite that file removes the proxy
first.

Only the MCP server declarations are recorded, never whole files — clients keep
caches and window positions in the same files and rewrite them constantly.
Environment variable and header **names** are covered; their values never are.

### Filters the child's environment

The proxy is the parent process, so it decides what the server inherits. A
filesystem server does not start life holding a cloud credential. Patterns match
the shape of a secret's name (`*_TOKEN`, `*_API_KEY`) rather than a vendor
prefix, which would strip configuration variables that merely share a word.

## Enforcement levels

| level | `deny` | `confirm` |
|---|---|---|
| `observe` (default) | recorded | recorded |
| `enforce` | **refused** | recorded, announced, relayed |
| `strict` | **refused** | **refused** |

```bash
mcp-guard -enforce -- ...          # deny only
mcp-guard -enforce=strict -- ...   # confirm too
mcp-guard -enforce=off -- ...      # back to observing
```

The two lists are not the same kind of thing. `deny` covers credentials, agent
configuration and shell startup files, which honest work never writes. `confirm`
covers `package.json`, Makefiles and shell scripts, which it writes all day. A
guard that refuses the second kind on the day it is installed is uninstalled the
same day.

### If it goes wrong

```bash
MCPGUARD_OFF=1
```

Set that in the client's environment and mcp-guard relays with no checks at all.
It is read before any config file is opened, so a broken policy — otherwise a
refusal to start, and therefore a server that never appears in your client —
cannot cost you your tools. Only affirmative values count, so `MCPGUARD_OFF=0`
does not disarm it.

## Reading it back

```bash
mcp-guard replay      # human-readable transcript of recorded sessions
mcp-guard eval --attack corpus/attack --benign ~/.mcp-guard/sessions
```

`replay` is offline and deterministic: no server is started, so the same log
always produces the same transcript. It shows which reply answered which
request, how long it took, what each `tools/call` targeted, and the server's own
stderr interleaved where it happened.

`eval` prints recall on the attack corpus and, more importantly, the false
positive rate on your own recorded traffic — with the number of calls printed
beside it, because a zero over two calls is not a rate.

## Measured, not asserted

On the development machine, at `enforce`: **28 tool calls of ordinary work over
two days, zero blocks.**

Deliberate probes are excluded from that count and listed in
`corpus/excluded-sessions.txt`; including them gives 11.1 blocks per week, which
is four correct refusals of attacks rather than friction to be tuned away.

`strict` produces roughly 30 refusals a week in the same workload, all of it one
exec-class tool. That does not improve with more data — it improves when a
confirm can be answered instead of refused.

This is one machine and one workload. Treat it as a starting point for your own
measurement, not as a result.

## What it does not do

- **`tools/list` is never blocked.** Refusing it leaves the client with no tools
  and a visibly broken server, so a rewritten description does reach the model
  before any call is refused. Pinning stops the effect, not the reading.
- **`confirm` cannot ask.** `elicitation/create` is the protocol's answer, and no
  client seen so far declares support for it, so at `strict` a confirm is refused
  with an explanation instead. Declared capabilities are logged, so this can be
  revisited with evidence.
- **Only stdio.** A server added over HTTP is unguarded, silently.
- **Taint does not cross servers.** One proxy per server means one session each,
  so fetching a poisoned page taints that proxy and the one running code never
  hears about it — even though the threat model is cross-server by nature.
- **A stdio proxy cannot see a server's own network traffic.** A server with
  built-in telemetry exfiltrates without a byte crossing this proxy.
- **Unicode NFC/NFD path normalisation is not implemented**, so a non-ASCII path
  may spell differently on macOS than a rule written on Linux.

## How this compares

`mcp-scan` is now **Snyk Agent Scan**: a scanner and inventory across thirteen
agents, MCP servers and skills, with a background mode reporting to a Snyk
instance. It requires an account and an API token before any scan runs.

The overlap is smaller than it looks. Agent Scan answers "what is installed and
does any of it look dangerous", across far more surface than this will ever
cover. mcp-guard answers "this call is about to write to `~/.ssh` — no", which
is a different question at a different moment.

Worth knowing: scanning a config **executes** the servers listed in it, to read
their tool descriptions. `mcp-guard approve` starts only the one server named on
its command line.

*(From reading its documentation, not from running it.)*

## Build from source

```bash
go build -o dist/mcp-guard ./cmd/mcp-guard
go test ./...
```

The race detector needs cgo and a C compiler:

```bash
CGO_ENABLED=1 go test -race ./...
```

Dependencies: `golang.org/x/sys` (Windows ACLs on the session log),
`fsnotify` (config watching), `yaml.v3` (policy files). Nothing else.

## A note on the session log

`~/.mcp-guard/sessions` holds the verbatim content of every tool call and every
tool result — file contents, API responses, any credential the agent happened to
read. It is one file per run, restricted to the owning user, and rotated. Treat
it like a password file and do not paste it into an issue.

## License

MIT. See [LICENSE](LICENSE).

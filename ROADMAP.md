# Roadmap

Status of every item in `docs/PLAN.md`, plus what was added beyond it.

Last checked: 29 July 2026.

---

## Stage 0 — the transparent pipe

- [x] Fork the real server, relay stdin/stdout/stderr untouched
- [x] Record every message to JSONL with direction and time
- [x] stderr relayed 1:1, never swallowed
- [x] No buffering; write and flush per message
- [x] Bodies kept as `json.RawMessage`, never re-marshalled
- [x] `bufio.Reader.ReadBytes`, not `Scanner` (the 64 KiB truncation trap)
- [x] Correct teardown: stdin EOF → wait → terminate → kill
- [x] Benign corpus collection starts here

**Done when:** the client works through `mcp-guard --` exactly as without it, and
the log holds a full session. ✅ Verified against
`@modelcontextprotocol/server-filesystem`.

## Stage 1 — protocol, not bytes

- [x] Full JSON-RPC parsing: request / response / notification / error
- [x] Both directions, including server-initiated requests
- [x] Batch frames (revision 2025-03-26) accepted
- [x] Correlation by **(direction, id)**, with TTL and sweeping
- [x] Session model: protocol version, peers, tool list, call history
- [x] `mcp-guard replay` — human-readable transcript, offline
- [x] Conformance test: identical message sequences with and without the proxy

**Done when:** replay is readable, no zombie processes, transparency holds. ✅

## Stage 2 — pinning

- [x] `mcp-guard approve` → `mcp-guard.lock`
- [x] Command, argv and environment **key names** recorded (never values)
- [x] Per tool: name, description, canonicalised input schema
- [x] JSON canonicalisation (RFC 8785 JCS) — the false-positive guard
- [x] Verification on every `tools/list` and before every `tools/call`
- [x] Mismatch → clear error naming `mcp-guard approve --diff`
- [x] `mcp-guard watch` — fsnotify on client configs
- [x] `mcp-guard verify` — pre-flight check, baseline outside the config directory
- [ ] A lock file for a real server committed to a repository — the workflow
      exists, nothing has actually been pinned in anger yet

**Done when:** the MCPoison scenario is blocked, `--diff` shows what changed. ✅

## Stage 3 — effect policy and taint

- [x] YAML policy: `allow` / `confirm` / `deny` by tool name and argument patterns
- [x] Path canonicalisation: `~`, `..`, env vars, symlinks, case, Windows 8.3
      short names, `\\?\` prefixes, NTFS alternate data streams
- [x] Comparison **after** resolution, never before
- [x] Default sensitive set: `~/.ssh`, `~/.aws`, `~/.gnupg`, git hooks,
      `**/mcp.json`, `**/.cursor/**`, `**/.claude/**`, shell startup files,
      autostart directories, `**/.env`
- [x] Separate exec class for tools with shell semantics
- [x] Taint by **source**: a result from fetch, mail, issues marks the session
- [x] Escalation: `allow` → `confirm` for sensitive effects once tainted
- [~] Confirmation mechanism — **cannot ask**. `elicitation/create` is the
      protocol-native way and the handshake log proves no connected client
      declares it, so at `strict` a confirm is refused with an explanation
      instead. Capabilities are now captured so this can be revisited with data.
- [ ] Environment filtering for the child process (`AWS_*`, `GITHUB_TOKEN`,
      `*_API_KEY`) — named in plan §1.3, `Options.Env` exists, no filter written

**Done when:** CurXecute is blocked **at the write**, and the whole benign corpus
produces zero blocks. First half ✅ (four spellings, end to end). Second half
**unproven** — see *Blocking everything else* below.

## Stage 4 — content signals and metrics

- [x] Normalisation pass before matching: base64, hex, percent-encoding, HTML
      comments, `display:none`, zero-width characters, homoglyphs, bidi overrides
- [x] Detector output is a **score, never a block**
- [x] Score raises taint only
- [x] Rules as data (YAML), not code
- [x] `mcp-guard eval --attack ... --benign ...`
- [x] Recall on the attack corpus — currently 100% over six published shapes
- [ ] False positives per rule on benign traffic — no data
- [ ] Blocks per week of ordinary use — no data
- [n/a] Port rules from the Python prototype — no prototype ever existed

## Stage 5 — optional, deliberately not planned ahead

- [ ] HTTP / SSE transport
- [ ] LLM classifier (opt-in, tainted sessions only, cached)
- [ ] Child-process sandboxing — **now has a concrete argument**: a server with
      built-in telemetry exfiltrates over its own network connection without a
      byte crossing this proxy. A stdio proxy is blind to it by construction.

---

## Testing infrastructure (plan §5)

- [x] Attack corpus — six published shapes in `corpus/attack/`
- [x] Malicious server fixture — the test binary re-executes itself as one
- [x] Replay harness: everything runs from `.jsonl`, no live servers, CI-safe
- [x] Recall metric
- [x] Observe is the default on install
- [~] Benign corpus — collecting, but only 2 tool calls so far
- [ ] Golden files for policy decisions (`input.jsonl` + `expected-verdicts.json`)
- [ ] False-positive rate per rule

---

## Added beyond the plan

- [x] Graduated enforcement: `observe` / `enforce` (deny only) / `strict`
- [x] `MCPGUARD_OFF=1` kill switch, read before any config file is opened
- [x] Windows ACL on the session log — Go's `0600` is nearly a no-op there
- [x] One log file per proxy run — several proxies shared one file and raced
- [x] Log rotation that never splits a record
- [x] stderr teed: relayed **and** recorded, so a transcript can say why a
      server died
- [x] Client and server capabilities captured from the handshake
- [x] CI on Windows and Linux, race detector on Linux
- [x] `CLAUDE.md` and `docs/` so a checkout carries its own context

---

## Blocking everything else

- [~] **Measure the false-positive rate on real traffic.** First real numbers,
      over 53 sessions and 12 tool calls in 54 hours, with one deliberate probe
      session excluded:

      blocks per week:  0.0 at enforce,  15.4 at strict

      `enforce` has produced no verdict at all on ordinary work. `strict` is
      fifteen times over the target of one, all of it `execute_blender_code`
      hitting the exec class — so strict is unusable alongside a Blender
      workflow until a confirm can be answered rather than refused.
      Twelve calls is a signal, not a sample.
- [ ] **Turn on `-enforce`.** The evidence now points that way rather than away,
      but it rests on twelve calls. Give it a week of ordinary work first.
- [ ] **Decide what to do about taint not crossing servers.** Found on real
      traffic and described in `CLAUDE.md`: one proxy per server means one
      session each, so fetching a poisoned page taints the fetch proxy and the
      blender proxy never hears about it. The threat model is cross-server by
      nature, which makes `exec.action_if_tainted` dead code in practice.
      Sharing state between processes — grouped by parent pid — is a design
      change with its own false-positive cost, so it waits on the line above.

## Product, once the above is answered

- [ ] Make the repository public — it is private, so nobody can install it, and
      it serves neither as a product nor as a portfolio piece today
- [ ] Tag a release and publish binaries (0 tags today)
- [ ] Get it installed by ten people who do not already know about it
- [ ] Only then: decide what the paid layer is, if any. The local binary is
      never it — fleet visibility, central policy that a developer cannot
      disable, and audit evidence are. Note that the kill switch and
      "flag beats policy file" are correct for a personal tool and backwards
      for a corporate control; that is a fork in the design, not a detail.

## Known limits, stated so they are not rediscovered

- `tools/list` is never blocked, so a poisoned description still reaches the
  model. Pinning stops the effect, not the reading.
- `confirm` cannot ask. See stage 3.
- Only stdio. A server added over HTTP is unguarded, silently.
- Unicode NFC/NFD path normalisation is not done — documented in
  `internal/fspath`, left out to avoid depending on `golang.org/x/text`.
- A stdio proxy cannot see a server's own outbound network traffic.

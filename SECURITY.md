# Security policy

## Reporting a vulnerability

Use [private vulnerability reporting](https://github.com/pterbsgame-netizen/mcp-guard/security/advisories/new).
Please do not open a public issue for anything that lets a call through that
policy should have refused.

Include the policy file, the tool call, and the verdict you expected. A session
log makes it reproducible — but read the warning below before attaching one.

This is a single-author project with no on-call rotation. Expect a first reply
within a week, not within an hour.

## Do not attach a raw session log

`~/.mcp-guard/sessions/*.jsonl` holds every tool call and every tool result
verbatim: file contents, API responses, and any credential the agent happened to
read along the way. Treat it like a password file. `mcp-guard replay` produces a
transcript you can read and trim before sending.

## Already known, please do not report as new

These are documented in the README and in the design. They are limits of the
approach, not defects, and a report about one of them tells us nothing we do not
already have written down:

- **`tools/list` is never blocked.** A poisoned tool description still reaches
  the model. Pinning stops the effect, not the reading.
- **Taint does not cross servers.** One proxy process per server means one
  session each, so content fetched through one server does not raise the level
  in another.
- **stdio only.** A server configured over HTTP is not guarded, and nothing
  says so.
- **A stdio proxy cannot see the server's own network traffic.** A server with
  built-in telemetry exfiltrates without a byte crossing the proxy.
- **Content signatures can be evaded.** By design they only raise the taint
  level and can never block, so evading them is expected rather than surprising.
- **`MCPGUARD_OFF=1` disables all checks.** It is an emergency switch for the
  person running the client, and it is deliberately not something the policy
  file can take away.

## What is worth reporting

- A path that reaches a `deny` target without producing a `deny` verdict —
  an encoding, a link, a normalisation form, an argument shape the extractor
  misses.
- A frame that passes the gate without being judged.
- A way to make the proxy fail open: crash it, make it relay after an internal
  error, or make it lose a verdict it had already reached.
- Anything that writes a secret into the log that should not be there, or that
  widens the log's permissions.

## Supported versions

The latest release only. There is not yet a version old enough to support in
parallel.

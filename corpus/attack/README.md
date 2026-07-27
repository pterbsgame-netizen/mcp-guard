# Attack corpus

One published-attack shape per file. These are the payloads a defender already
knows about, so recall here is the easy number: every signature was written
after reading these, and a high score proves the rule matches its own example,
not that it generalises.

They earn their place anyway. They are the regression set — a rule change that
quietly stops catching one of these shows up immediately — and they are the
worked examples for anyone reading the ruleset.

The genuinely informative measurement is the false-positive rate on real
traffic, which lives nowhere near this directory and cannot be manufactured. See
`mcp-guard eval --benign`.

Sources are named in each file. The text is reconstructed to the shape of the
public write-up, not copied from a victim.

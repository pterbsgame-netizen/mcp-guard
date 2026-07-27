package policy

import (
	"encoding/json"
)

// Limits on how much of an argument tree to walk. A tool result can be
// megabytes; arguments are small, and anything that is not is not a path.
const (
	maxDepth      = 12
	maxCandidates = 256
)

// extractPaths returns every string in a call's arguments that might name a
// path, wherever it sits in the structure.
//
// It deliberately does not care which argument is "the path one". That would
// need per-tool knowledge of every server anyone might install, and getting it
// wrong means a rule silently covers nothing. Values are matched against the
// rules whatever they are called, so an unfamiliar server with a "destination"
// or "targets" argument is covered on the day it is installed.
func extractPaths(args json.RawMessage) []string {
	if len(args) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(args, &v); err != nil {
		return nil
	}
	var out []string
	walk(v, 0, &out)
	return out
}

func walk(v any, depth int, out *[]string) {
	if depth > maxDepth || len(*out) >= maxCandidates {
		return
	}
	switch t := v.(type) {
	case string:
		if looksLikePath(t) {
			*out = append(*out, t)
		}
	case []any:
		for _, e := range t {
			walk(e, depth+1, out)
		}
	case map[string]any:
		// Keys are not walked: an argument name is chosen by the server, not
		// by whoever is trying to reach a file.
		for _, e := range t {
			walk(e, depth+1, out)
		}
	}
}

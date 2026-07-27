package replay

import (
	"bytes"
	"strings"
	"testing"
)

// log is the live Claude Desktop trace: the client's initialize and the
// server's roots/list both use id 0, and roots/list arrives while the client's
// tools/list is still outstanding.
const log = `{"seq":1,"sid":"aaaa","t":"2026-07-26T23:46:42.000Z","ev":"start","argv":["npx","-y","@modelcontextprotocol/server-filesystem","C:\\Users\\peter\\dev"],"pid":15720}
{"seq":2,"sid":"aaaa","t":"2026-07-26T23:46:42.100Z","dir":"c2s","msg":{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"claude-ai","version":"0.1.0"}}}}
{"seq":3,"sid":"aaaa","t":"2026-07-26T23:46:42.150Z","dir":"s2c","msg":{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"secure-filesystem-server","version":"0.2.0"}}}}
{"seq":4,"sid":"aaaa","t":"2026-07-26T23:46:42.160Z","dir":"c2s","msg":{"jsonrpc":"2.0","method":"notifications/initialized"}}
{"seq":5,"sid":"aaaa","t":"2026-07-26T23:46:42.200Z","dir":"c2s","msg":{"jsonrpc":"2.0","id":1,"method":"tools/list"}}
{"seq":6,"sid":"aaaa","t":"2026-07-26T23:46:42.210Z","dir":"s2c","msg":{"jsonrpc":"2.0","id":0,"method":"roots/list"}}
{"seq":7,"sid":"aaaa","t":"2026-07-26T23:46:42.260Z","dir":"c2s","msg":{"jsonrpc":"2.0","id":0,"result":{"roots":[]}}}
{"seq":8,"sid":"aaaa","t":"2026-07-26T23:46:42.500Z","dir":"s2c","msg":{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_text_file","description":"Read a file.","inputSchema":{"type":"object"}},{"name":"write_file","description":"Write a file.","inputSchema":{"type":"object"}}]}}}
{"seq":9,"sid":"aaaa","t":"2026-07-26T23:46:43.000Z","dir":"c2s","msg":{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"hello.txt"}}}}
{"seq":10,"sid":"aaaa","t":"2026-07-26T23:46:43.050Z","dir":"s2c","msg":{"jsonrpc":"2.0","id":2,"result":{"isError":true,"content":[{"type":"text","text":"Access denied"}]}}}
{"seq":11,"sid":"aaaa","t":"2026-07-26T23:46:44.000Z","dir":"s2c","raw":"npm warn: deprecated glob@10.5.0"}
{"seq":12,"sid":"aaaa","t":"2026-07-26T23:46:45.000Z","ev":"exit","code":0}
{"seq":1,"sid":"bbbb","t":"2026-07-27T00:10:00.000Z","ev":"start","argv":["npx","server"],"pid":42}
{"seq":2,"sid":"bbbb","t":"2026-07-27T00:10:00.100Z","dir":"c2s","msg":{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}}
`

func TestReadTranscript(t *testing.T) {
	var out bytes.Buffer
	if err := Read(&out, strings.NewReader(log)); err != nil {
		t.Fatalf("Read: %v", err)
	}
	got := out.String()
	t.Logf("transcript:\n%s", got)

	want := []string{
		// Two runs, split by session id.
		"session aaaa",
		"session bbbb",
		"server: npx -y @modelcontextprotocol/server-filesystem",

		// Direction is visible at a glance.
		"->  initialize  id=0",
		"<-  result <- initialize  id=0",

		// The server's roots/list must be attributed to roots/list, not to the
		// client's initialize, which used the same id.
		"<-  roots/list  id=0",
		"->  result <- roots/list  id=0",

		// tools/list is answered last, out of order, and timed from its own
		// request rather than from whatever reply came before it.
		"<-  result <- tools/list  id=1  300ms",

		// A tool call names its tool.
		"tool=read_text_file",

		// Non-JSON server output survives into the transcript.
		"npm warn: deprecated",

		"[exit] code=0",
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("transcript is missing %q", w)
		}
	}

	// The summary must reflect the session model, including the failed call
	// reported through isError rather than as a JSON-RPC error.
	for _, w := range []string{
		"protocol 2025-06-18",
		"client claude-ai 0.1.0",
		"server secure-filesystem-server 0.2.0",
		"2 tools advertised, 1 calls, 1 failed",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("summary is missing %q", w)
		}
	}
}

// TestUnparseableLineDoesNotStop covers a truncated log, which is what a log
// looks like if the machine lost power mid-write.
func TestUnparseableLineDoesNotStop(t *testing.T) {
	broken := `{"seq":1,"sid":"aaaa","t":"2026-07-26T23:46:42.000Z","ev":"start","argv":["x"],"pid":1}
{"seq":2,"sid":"aaaa","dir":"c2s","msg":{"jsonrpc":"2.0","id":0,"me
{"seq":3,"sid":"aaaa","t":"2026-07-26T23:46:43.000Z","ev":"exit","code":0}
`
	var out bytes.Buffer
	if err := Read(&out, strings.NewReader(broken)); err != nil {
		t.Fatalf("Read: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "not valid JSONL") {
		t.Errorf("the torn line was not reported:\n%s", got)
	}
	if !strings.Contains(got, "[exit]") {
		t.Errorf("replay stopped at the torn line instead of carrying on:\n%s", got)
	}
}

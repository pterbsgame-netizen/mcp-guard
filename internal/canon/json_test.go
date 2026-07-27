package canon

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestNumbers covers RFC 8785's number rules, which are ECMAScript's, not Go's.
// The boundaries are where strconv and ECMAScript disagree about when to switch
// to exponential notation, so these are the cases that would silently produce a
// hash no other implementation agrees with.
func TestNumbers(t *testing.T) {
	tests := []struct{ in, want string }{
		{"0", "0"},
		{"-0", "0"},
		{"1", "1"},
		{"1.0", "1"},
		{"-1.5", "-1.5"},
		{"100", "100"},
		{"1e2", "100"},

		// Integers stay plain right up to 1e21, then flip to exponential.
		{"1e20", "100000000000000000000"},
		{"1e21", "1e+21"},

		// Small values stay plain down to 1e-6, then flip.
		{"0.000001", "0.000001"},
		{"1e-7", "1e-7"},

		{"333333333.3333333", "333333333.3333333"},
		{"5e-324", "5e-324"},                                  // smallest denormal
		{"1.7976931348623157e308", "1.7976931348623157e+308"}, // largest finite
	}
	for _, tt := range tests {
		got, err := formatNumber(json.Number(tt.in))
		if err != nil {
			t.Errorf("formatNumber(%s): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("formatNumber(%s) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

// TestKeyOrderIsUTF16 is the case where sorting by UTF-16 code units and
// sorting by UTF-8 bytes disagree. U+FFFF is EF BF BF in UTF-8 and so sorts
// below the emoji's F0 9F 98 80; in UTF-16 the emoji is the surrogate pair
// D83D DE00 and sorts below FFFF. Getting this backwards produces hashes that
// no other JCS implementation reproduces.
func TestKeyOrderIsUTF16(t *testing.T) {
	got, err := JSON([]byte("{\"￿\":1,\"\U0001F600\":2}"))
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	want := "{\"\U0001F600\":2,\"￿\":1}"
	if string(got) != want {
		t.Errorf("key order = %q, want %q", got, want)
	}
}

func TestCanonicalForm(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{
			name: "keys are sorted and whitespace dropped",
			in:   `{ "b": 1,  "a": 2, "C": 3 }`,
			// Uppercase sorts before lowercase: this is code-unit order, not
			// a locale-aware or case-insensitive one.
			want: `{"C":3,"a":2,"b":1}`,
		},
		{
			name: "array order is meaningful and preserved",
			in:   `[3,1,2]`,
			want: `[3,1,2]`,
		},
		{
			name: "nested objects are sorted too",
			in:   `{"z":{"y":1,"x":2},"a":[{"q":1,"p":2}]}`,
			want: `{"a":[{"p":2,"q":1}],"z":{"x":2,"y":1}}`,
		},
		{
			// Long escapes collapse to the short forms, so two servers that
			// escape a tab differently still hash the same.
			name: "control character escapes are normalised",
			in:   `{"s":"a\u0009b\u000Ac d"}`,
			want: `{"s":"a\tb\nc d"}`,
		},
		{
			// encoding/json would emit < here, which is valid JSON but
			// not the canonical form.
			name: "html characters are not escaped",
			in:   `{"s":"<a> & </a>"}`,
			want: `{"s":"<a> & </a>"}`,
		},
		{
			name: "literals",
			in:   `{"a":null,"b":true,"c":false}`,
			want: `{"a":null,"b":true,"c":false}`,
		},
		{
			name: "empty containers",
			in:   `{"a":{},"b":[]}`,
			want: `{"a":{},"b":[]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JSON([]byte(tt.in))
			if err != nil {
				t.Fatalf("JSON(%s): %v", tt.in, err)
			}
			if string(got) != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestRejects(t *testing.T) {
	tests := []struct{ name, in, wantErr string }{
		{
			// A parser that resolves duplicates silently lets a server ship a
			// schema that reads one way to us and another to the agent.
			name:    "duplicate keys",
			in:      `{"description":"safe","description":"evil"}`,
			wantErr: "duplicate object key",
		},
		{
			name:    "trailing content",
			in:      `{} garbage`,
			wantErr: "trailing content",
		},
		{
			name:    "not json",
			in:      `{`,
			wantErr: "canon:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := JSON([]byte(tt.in))
			if err == nil {
				t.Fatalf("JSON(%s) = no error, want one", tt.in)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

// TestHashIgnoresPresentation is the property the whole feature rests on: a
// server may re-serialise a schema between runs without meaning anything by it,
// and that must not read as tampering.
func TestHashIgnoresPresentation(t *testing.T) {
	original := `{
	  "type": "object",
	  "properties": {
	    "path": {"type": "string"},
	    "head": {"description": "first N lines", "type": "number"}
	  },
	  "required": ["path"]
	}`
	reserialised := `{"required":["path"],"properties":{"head":{"type":"number","description":"first N lines"},"path":{"type":"string"}},"type":"object"}`

	a, err := Hash([]byte(original))
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	b, err := Hash([]byte(reserialised))
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if a != b {
		t.Errorf("reordering the same schema changed its hash:\n  %s\n  %s", a, b)
	}

	// And a real change must move it. Widening a schema is exactly what a
	// silent post-approval swap looks like.
	widened := `{"type":"object","properties":{"path":{"type":"string"},"head":{"type":"number","description":"first N lines"}},"required":[]}`
	c, err := Hash([]byte(widened))
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if c == a {
		t.Error("dropping a required field did not change the hash")
	}
}

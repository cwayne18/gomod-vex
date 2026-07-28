package llm

import "testing"

func TestParseVerdict(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"plain", `{"exploitable":"likely","confidence":"high","rationale":"reachable parser"}`, "likely"},
		{"fenced", "```json\n{\"exploitable\":\"unlikely\",\"confidence\":\"medium\",\"rationale\":\"x\"}\n```", "unlikely"},
		{"prose_wrapped", "Here is my answer:\n{\"exploitable\":\"unknown\",\"confidence\":\"low\",\"rationale\":\"y\"}\nThanks", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := parseVerdict(tc.content)
			if err != nil {
				t.Fatal(err)
			}
			if v.Exploitable != tc.want {
				t.Errorf("got %q, want %q", v.Exploitable, tc.want)
			}
		})
	}
}

func TestParseVerdictNonJSON(t *testing.T) {
	v, err := parseVerdict("I cannot determine this.")
	if err != nil {
		t.Fatal(err)
	}
	if v.Exploitable != "unknown" {
		t.Errorf("expected unknown fallback, got %q", v.Exploitable)
	}
}

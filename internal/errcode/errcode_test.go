package errcode

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var codePattern = regexp.MustCompile(`^AG[0-9]{3}$`)

// Every code is well formed, unique, and listed in docs/ERRORS.md with its
// title and what to do; the document lists no other code.
func TestRegistryMatchesTheDocs(t *testing.T) {
	doc, err := os.ReadFile("../../docs/ERRORS.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[Code][]string{}
	for line := range strings.SplitSeq(string(doc), "\n") {
		if !strings.HasPrefix(line, "| AG") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		documented[Code(cells[0])] = cells
	}
	seen := map[Code]bool{}
	for _, e := range registry {
		if !codePattern.MatchString(string(e.Code)) {
			t.Errorf("%s is not AG and three digits", e.Code)
		}
		if seen[e.Code] {
			t.Errorf("%s is registered twice", e.Code)
		}
		seen[e.Code] = true
		if e.Title == "" || e.Msg == "" {
			t.Errorf("%s has no title or message", e.Code)
		}
		cells, ok := documented[e.Code]
		switch {
		case !ok:
			t.Errorf("%s is missing from docs/ERRORS.md", e.Code)
		case len(cells) != 3 || cells[1] != e.Title || strings.TrimSpace(cells[2]) == "":
			t.Errorf("docs/ERRORS.md row of %s = %q, want | code | %s | what to do |", e.Code, cells, e.Title)
		}
	}
	for code := range documented {
		if !seen[code] {
			t.Errorf("docs/ERRORS.md lists %s, which is not registered", code)
		}
	}
}

func TestNewPanicsOnAnUnregisteredCode(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New accepted an unregistered code")
		}
	}()
	New("AG999")
}

package ports

import (
	"reflect"
	"testing"
)

func TestParseFlag(t *testing.T) {
	got, err := ParseFlag(" 8000-8100, 80 ,502,8050-8200,81")
	if err != nil {
		t.Fatal(err)
	}
	want := Ceiling{{From: 80, To: 81}, {From: 502, To: 502}, {From: 8000, To: 8200}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parsed = %v, want %v", got, want)
	}
	if got.String() != "80-81,502,8000-8200" {
		t.Errorf("String = %q", got.String())
	}
	if c, err := ParseFlag(""); err != nil || c != nil {
		t.Errorf("empty = %v, %v; want no ceiling", c, err)
	}
}

func TestParseRefusesBadEntries(t *testing.T) {
	for _, bad := range []string{"0", "65536", "-1", "abc", "100-99", "80-", "-80", "80-90-100", "8000-x"} {
		if _, err := Parse([]string{bad}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	tooMany := make([]string, MaxRanges+1)
	for i := range tooMany {
		tooMany[i] = "80"
	}
	if _, err := Parse(tooMany); err == nil {
		t.Error("accepted more than MaxRanges entries")
	}
}

func TestCeilingAllows(t *testing.T) {
	c := Ceiling{{From: 80, To: 80}, {From: 8000, To: 8100}}
	for port, want := range map[uint16]bool{80: true, 81: false, 8000: true, 8100: true, 8101: false} {
		if got := c.Allows(port); got != want {
			t.Errorf("Allows(%d) = %v, want %v", port, got, want)
		}
	}
	if !Ceiling(nil).Allows(22) {
		t.Error("no ceiling must allow every port")
	}
}

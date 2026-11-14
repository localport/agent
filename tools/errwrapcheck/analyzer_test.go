package main

import (
	"slices"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), Analyzer, "github.com/localport/agent/a")
}

func TestWrapOperands(t *testing.T) {
	for format, want := range map[string][]int{
		"%w: x":         {0},
		"%s %w":         {1},
		"%*d %w":        {2},
		"%.*f %w":       {2},
		"%[2]s %[1]w":   {0},
		"%[2]w %w":      {1, 2},
		"%% %w":         {0},
		"%-08.3f %w %w": {1, 2},
		"no verbs":      nil,
	} {
		got, ok := wrapOperands(format)
		if !ok || !slices.Equal(got, want) {
			t.Errorf("wrapOperands(%q) = %v, %v; want %v", format, got, ok, want)
		}
	}
	if _, ok := wrapOperands("%[x]w"); ok {
		t.Error("a malformed index was accepted")
	}
}

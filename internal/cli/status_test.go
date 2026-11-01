package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestStatusPrintsServiceAndDevices(t *testing.T) {
	file := asRoot(t, &fakeManager{installed: true, mainPID: 42})
	writeDevices(t, file)
	var out bytes.Buffer
	if err := printStatus(context.Background(), &out); err != nil {
		t.Fatalf("status = %v", err)
	}
	for _, want := range []string{"running, pid 42", "config     " + file.Path, "device     " + deviceRef("factory.gw-01").String(), "run_as_agent false", "launcher   session auth"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status output lacks %q:\n%s", want, out.String())
		}
	}
}

// Without a readable config, status prints the service state only.
func TestStatusWithoutConfigPrintsServiceOnly(t *testing.T) {
	asRoot(t, &fakeManager{})
	var out bytes.Buffer
	if err := printStatus(context.Background(), &out); err != nil {
		t.Fatalf("status = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "not installed") || !strings.Contains(got, "config     none at") || strings.Contains(got, "device ") {
		t.Fatalf("status output:\n%s", got)
	}
}

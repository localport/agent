package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// localport.dev serves tunnel hostnames, region zones and edge DNS only.
// Services and docs live on localport.io. A URL with a path on localport.dev
// is a misplaced services link. The bare apex has no address record. A tunnel
// or device host with a scheme and no path is allowed.
var (
	tunnelDomainWithPath = regexp.MustCompile(`https?://[a-z0-9.-]*localport\.dev/\S`)
	tunnelDomainApex     = regexp.MustCompile(`https?://localport\.dev\b`)
)

func TestNoServicesURLOnTheTunnelDomain(t *testing.T) {
	root := ".."
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, hit := range tunnelDomainWithPath.FindAll(src, -1) {
			t.Errorf("%s: %q puts a path on the tunnel domain; services and docs live on localport.io", path, hit)
		}
		for _, hit := range tunnelDomainApex.FindAll(src, -1) {
			t.Errorf("%s: %q is the tunnel domain apex, which has no address record", path, hit)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

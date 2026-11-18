//go:build darwin

package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// codesignVerify accepts an ad-hoc bundle signed as io.localport.session in
// a build without a release certificate, and refuses another identifier, or
// any ad-hoc bundle once the build names a release certificate.
func TestCodesignVerify(t *testing.T) {
	sign := func(t *testing.T, identifier string) string {
		t.Helper()
		bundle := filepath.Join(t.TempDir(), AppName)
		exe := filepath.Join(bundle, appExecutable)
		if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(bundle, "Contents", "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>`+identifier+`</string>
<key>CFBundleExecutable</key><string>localport-session</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
`)
		bin, err := os.ReadFile("/usr/bin/true")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(exe, bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(codesignPath, "--force", "--sign", "-", "--options", "runtime", "--identifier", identifier, bundle).CombinedOutput(); err != nil {
			t.Fatalf("codesign: %v: %s", err, out)
		}
		return bundle
	}
	ctx := context.Background()
	ours := sign(t, AppBundleID)
	if err := codesignVerify(ctx, ours); err != nil {
		t.Fatalf("ad-hoc build, our bundle: %v", err)
	}
	if err := codesignVerify(ctx, sign(t, "io.example.other")); !errors.Is(err, errAppInvalid) {
		t.Fatalf("another identifier = %v, want errAppInvalid", err)
	}
	t.Cleanup(func() { releaseCertSHA1 = "" })
	releaseCertSHA1 = "fe8dd57e9c2c72b26bee46df1a0769ab217516ea"
	if err := codesignVerify(ctx, ours); !errors.Is(err, errAppInvalid) {
		t.Fatalf("release build, ad-hoc bundle = %v, want errAppInvalid", err)
	}
}

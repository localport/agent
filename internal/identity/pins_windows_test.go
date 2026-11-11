package identity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Reset discards a corrupt pin file that another process holds open without
// delete sharing for a moment: the removal waits out the sharing violation.
func TestDesktopPinResetWaitsOutASharingViolation(t *testing.T) {
	store := deviceTicketKeys(t)
	path := filepath.Join(store.Dir(deviceRef), desktopPinsFile)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	// os.Open shares read and write but not delete, as a scanner would.
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); !isSharingViolation(err) {
		held.Close()
		t.Fatalf("Remove while held = %v, want a sharing violation", err)
	}
	time.AfterFunc(500*time.Millisecond, func() { held.Close() })
	if r, err := store.mustDesktopPins(t).Reset(context.Background(), "vnc"); err != nil || r != ResetDiscarded {
		t.Fatalf("Reset = %v, %v; want ResetDiscarded once the handle closes", r, err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pin file after Reset: %v", err)
	}
}

//go:build linux

package status

import (
	"strings"
	"testing"
)

func TestReadRejectsReusedProcessIdentity(t *testing.T) {
	directory := t.TempDir()
	store := NewStore(directory)
	if err := store.Update(func(snapshot *Snapshot) { snapshot.Phase = "ready" }); err != nil {
		t.Fatal(err)
	}
	live, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	if live.Phase != "ready" || live.ProcessStart == "" {
		t.Fatalf("unexpected live snapshot: %#v", live)
	}
	if err := store.Update(func(snapshot *Snapshot) { snapshot.ProcessStart = "not-this-process" }); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(directory); err == nil || !strings.Contains(err.Error(), "identity does not match") {
		t.Fatalf("expected stale process identity, got %v", err)
	}
}

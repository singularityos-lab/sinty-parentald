package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-parentald/internal/policy"
)

func newService(t *testing.T, uid uint32) (*Service, policy.Store) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "passwd"), []byte("parent:x:1000:1000::/:/bin/sh\nkid:x:1001:1001::/:/bin/sh\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "group"), []byte("wheel:x:10:parent\n"), 0o644)
	store := policy.Store{Dir: filepath.Join(dir, "p"), Passwd: filepath.Join(dir, "passwd"), Group: filepath.Join(dir, "group")}
	return New(store, func(dbus.Sender) (uint32, error) { return uid, nil }), store
}

func TestParentSetsKidPolicy(t *testing.T) {
	s, store := newService(t, 1000)
	if err := s.SetPolicy(":1.4", "kid", "[Web]\nFilter=true\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.Path("kid")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPolicy(":1.4", "kid", "[Other]\n"); err == nil || err.Name != Iface+".Error.Invalid" {
		t.Fatalf("got %v", err)
	}
	if err := s.ClearPolicy(":1.4", "kid"); err != nil {
		t.Fatal(err)
	}
}

func TestKidCannotLiftOwnLimits(t *testing.T) {
	s, store := newService(t, 1001)
	os.MkdirAll(store.Dir, 0o755)
	os.WriteFile(store.Path("kid"), []byte("[Time]\n"), 0o644)
	if err := s.ClearPolicy(":1.9", "kid"); err == nil || err.Name != "org.freedesktop.DBus.Error.AccessDenied" {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(store.Path("kid")); err != nil {
		t.Fatal("the kid removed their own policy")
	}
}

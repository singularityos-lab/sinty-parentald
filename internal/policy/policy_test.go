package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) Store {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "passwd"), []byte(
		"root:x:0:0::/root:/bin/sh\n"+
			"nobody:x:65534:65534::/:/bin/false\n"+
			"daemon:x:2:2::/:/bin/false\n"+
			"parent:x:1000:1000::/home/parent:/bin/sh\n"+
			"kid:x:1001:1001::/home/kid:/bin/sh\n"+
			"guest:x:1002:1002::/home/guest:/bin/sh\n"+
			"owner:x:1003:10::/home/owner:/bin/sh\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "group"), []byte(
		"root:x:0:\nwheel:x:10:parent\nusers:x:100:kid,guest\n"), 0o644)
	return Store{Dir: filepath.Join(dir, "parental"), Passwd: filepath.Join(dir, "passwd"), Group: filepath.Join(dir, "group")}
}

func TestWhoMayChange(t *testing.T) {
	s := fixture(t)
	cases := []struct {
		caller uint32
		target string
		ok     bool
	}{
		{0, "kid", true},
		{1000, "kid", true},
		{1003, "kid", true},
		{1000, "parent", false},
		{1001, "kid", false},
		{1002, "kid", false},
		{4242, "kid", false},
	}
	for _, c := range cases {
		if got := s.MayChange(c.caller, c.target); got != c.ok {
			t.Errorf("uid %d on %s: %v", c.caller, c.target, got)
		}
	}
}

func TestSetAndClear(t *testing.T) {
	s := fixture(t)
	data := "[Apps]\nBlocked=org.example.Game\n\n# bedtime\n[Time]\nBedtimeStart=1260\n"
	if err := s.Set("kid", data); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(s.Path("kid"))
	if err != nil || string(got) != data {
		t.Fatalf("stored %q %v", got, err)
	}
	if fi, _ := os.Stat(s.Path("kid")); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if err := s.Clear("kid"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Path("kid")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("policy still there")
	}
	if err := s.Clear("kid"); err != nil {
		t.Fatalf("clearing twice: %v", err)
	}
	left, _ := os.ReadDir(s.Dir)
	if len(left) != 0 {
		t.Fatalf("left behind %v", left)
	}
}

func TestRefusals(t *testing.T) {
	s := fixture(t)
	for _, user := range []string{"root", "daemon", "nobody", "missing", "../kid", "-kid", ""} {
		if err := s.Set(user, "[Apps]\n"); !errors.Is(err, ErrUser) {
			t.Errorf("user %q: %v", user, err)
		}
	}
	for _, data := range []string{"[Session]\nx=1\n", "[Apps\n", "loose line\n", "[Apps]\n=1\n", string(make([]byte, MaxSize+1))} {
		if err := s.Set("kid", data); !errors.Is(err, ErrPolicy) {
			t.Errorf("policy %.20q: %v", data, err)
		}
	}
}

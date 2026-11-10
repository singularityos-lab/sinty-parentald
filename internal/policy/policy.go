// Package policy validates and stores the parental controls policy of each
// account as /var/lib/singularity/parental/USER.conf, the file the session
// reads to enforce app, time and web limits.
package policy

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const MaxSize = 64 * 1024

var (
	ErrUser   = errors.New("not a regular account")
	ErrPolicy = errors.New("not a valid policy")
)

var groups = map[string]bool{"Apps": true, "Time": true, "Web": true}

func ValidName(name string) bool {
	if name == "" || len(name) > 64 || name[0] == '-' || name[0] == '.' {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// Validate accepts a key file whose groups are only Apps, Time and Web.
func Validate(data string) error {
	if len(data) > MaxSize {
		return fmt.Errorf("%w: larger than %d bytes", ErrPolicy, MaxSize)
	}
	sc := bufio.NewScanner(strings.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), MaxSize)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || line[0] == '#':
		case line[0] == '[':
			if !strings.HasSuffix(line, "]") || !groups[line[1:len(line)-1]] {
				return fmt.Errorf("%w: line %d: unknown group %s", ErrPolicy, n, line)
			}
		case strings.Contains(line, "="):
			if strings.TrimSpace(line[:strings.Index(line, "=")]) == "" {
				return fmt.Errorf("%w: line %d: empty key", ErrPolicy, n)
			}
		default:
			return fmt.Errorf("%w: line %d", ErrPolicy, n)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	return nil
}

type Account struct {
	Name string
	UID  uint32
	GID  uint32
}

// Accounts reads an /etc/passwd style file.
func Accounts(path string) ([]Account, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Account
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 4 {
			continue
		}
		uid, err1 := strconv.ParseUint(fields[2], 10, 32)
		gid, err2 := strconv.ParseUint(fields[3], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, Account{fields[0], uint32(uid), uint32(gid)})
	}
	return out, sc.Err()
}

// Admins lists the members of the groups that may administer the machine,
// by name, and the ids of those groups.
func Admins(path string) (map[string]bool, map[uint32]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	members := map[string]bool{}
	gids := map[uint32]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 4 {
			continue
		}
		switch fields[0] {
		case "wheel", "sudo", "admin":
		default:
			continue
		}
		if gid, err := strconv.ParseUint(fields[2], 10, 32); err == nil {
			gids[uint32(gid)] = true
		}
		for _, m := range strings.Split(fields[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members[m] = true
			}
		}
	}
	return members, gids, sc.Err()
}

type Store struct {
	Dir    string
	Passwd string
	Group  string
}

func (s Store) account(name string) (Account, bool) {
	accounts, err := Accounts(s.Passwd)
	if err != nil {
		return Account{}, false
	}
	for _, a := range accounts {
		if a.Name == name {
			return a, true
		}
	}
	return Account{}, false
}

func (s Store) byUID(uid uint32) (Account, bool) {
	accounts, err := Accounts(s.Passwd)
	if err != nil {
		return Account{}, false
	}
	for _, a := range accounts {
		if a.UID == uid {
			return a, true
		}
	}
	return Account{}, false
}

// MayChange tells whether the account with uid caller may change the policy
// of target: root always, an administrator for anyone but themselves.
func (s Store) MayChange(caller uint32, target string) bool {
	if caller == 0 {
		return true
	}
	who, ok := s.byUID(caller)
	if !ok || who.Name == target {
		return false
	}
	members, gids, err := Admins(s.Group)
	if err != nil {
		return false
	}
	return members[who.Name] || gids[who.GID]
}

func (s Store) target(user string) error {
	if !ValidName(user) {
		return ErrUser
	}
	a, ok := s.account(user)
	if !ok || a.UID < 1000 || a.UID == 65534 {
		return ErrUser
	}
	return nil
}

func (s Store) Path(user string) string {
	return filepath.Join(s.Dir, user+".conf")
}

func (s Store) Set(user, data string) error {
	if err := s.target(user); err != nil {
		return err
	}
	if err := Validate(data); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, "."+user+".conf.")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.WriteString(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, s.Path(user))
}

func (s Store) Clear(user string) error {
	if err := s.target(user); err != nil {
		return err
	}
	if err := os.Remove(s.Path(user)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

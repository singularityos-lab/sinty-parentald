// Package service exports dev.sinty.Parental1 on the system bus.
package service

import (
	"errors"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"

	"github.com/singularityos-lab/sinty-parentald/internal/policy"
)

const (
	Name  = "dev.sinty.Parental1"
	Path  = dbus.ObjectPath("/dev/sinty/Parental1")
	Iface = "dev.sinty.Parental1"
)

type Caller func(sender dbus.Sender) (uint32, error)

type Service struct {
	mu     sync.Mutex
	store  policy.Store
	caller Caller
	emit   func(user string)
}

func New(store policy.Store, caller Caller) *Service {
	return &Service{store: store, caller: caller, emit: func(string) {}}
}

func (s *Service) Export(conn *dbus.Conn) error {
	if s.caller == nil {
		s.caller = func(sender dbus.Sender) (uint32, error) {
			var uid uint32
			err := conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, string(sender)).Store(&uid)
			return uid, err
		}
	}
	s.emit = func(user string) { conn.Emit(Path, Iface+".Changed", user) }
	if err := conn.Export(s, Path, Iface); err != nil {
		return err
	}
	node := &introspect.Node{
		Name: string(Path),
		Interfaces: []introspect.Interface{introspect.IntrospectData, {
			Name:    Iface,
			Methods: introspect.Methods(s),
			Signals: []introspect.Signal{{Name: "Changed", Args: []introspect.Arg{{Name: "user", Type: "s"}}}},
		}},
	}
	return conn.Export(introspect.NewIntrospectable(node), Path, "org.freedesktop.DBus.Introspectable")
}

func (s *Service) allowed(sender dbus.Sender, user string) *dbus.Error {
	uid, err := s.caller(sender)
	if err != nil || !s.store.MayChange(uid, user) {
		return dbus.NewError("org.freedesktop.DBus.Error.AccessDenied",
			[]interface{}{fmt.Sprintf("only an administrator other than %s may change their limits", user)})
	}
	return nil
}

func failure(err error) *dbus.Error {
	if err == nil {
		return nil
	}
	if errors.Is(err, policy.ErrUser) || errors.Is(err, policy.ErrPolicy) {
		return dbus.NewError(Iface+".Error.Invalid", []interface{}{err.Error()})
	}
	return dbus.NewError(Iface+".Error.Failed", []interface{}{err.Error()})
}

func (s *Service) SetPolicy(sender dbus.Sender, user, data string) *dbus.Error {
	if e := s.allowed(sender, user); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.Set(user, data); err != nil {
		return failure(err)
	}
	s.emit(user)
	return nil
}

func (s *Service) ClearPolicy(sender dbus.Sender, user string) *dbus.Error {
	if e := s.allowed(sender, user); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.Clear(user); err != nil {
		return failure(err)
	}
	s.emit(user)
	return nil
}

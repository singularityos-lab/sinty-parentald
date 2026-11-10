package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-parentald/internal/policy"
	"github.com/singularityos-lab/sinty-parentald/internal/service"
)

func main() {
	dir := flag.String("dir", "/var/lib/singularity/parental", "where the policies are kept")
	flag.Parse()
	log.SetFlags(0)

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		log.Fatalf("system bus: %v", err)
	}
	defer conn.Close()
	svc := service.New(policy.Store{Dir: *dir, Passwd: "/etc/passwd", Group: "/etc/group"}, nil)
	if err := svc.Export(conn); err != nil {
		log.Fatalf("export: %v", err)
	}
	reply, err := conn.RequestName(service.Name, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("cannot own %s: %v", service.Name, err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

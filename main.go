package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

func main() {

	log.SetFlags(log.Ldate | log.Lmicroseconds)

	f := SetFlags()
	flag.Parse()

	fBytes, _ := json.MarshalIndent(f, "", "\t")
	log.Printf("\n%s\n", string(fBytes))

	neti := NewNetInterface()
	neti.LoadIfInterface()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	uname, _ := GetOSUnamer()
	unameBytes, _ := json.MarshalIndent(uname, "", "\t")
	log.Printf("\n%s\n", string(unameBytes))

	log.Println("tc-filter start...")
	log.Printf("process pid: %d\n", os.Getpid())

	o := NewOutput(neti)
	p := NewTcProbe(neti, o)

	p.Start(f)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	<-stopper

	p.Stop()

	log.Println("Received signal, exiting program..")

}

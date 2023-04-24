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

	f := SetFlags()
	flag.Parse()

	log.Printf("%+v\n", f)

	neti := NewNetInterface()
	neti.LoadIfInterface()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	uname, _ := GetOSUnamer()
	unameBytes, _ := json.MarshalIndent(uname, "", "\t")
	log.Println(string(unameBytes))

	log.Println("tc-filter start...")
	log.Printf("process pid: %d\n", os.Getpid())

	p := NewTcProbe(neti)

	p.Start()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	<-stopper

	p.Stop()

	log.Println("Received signal, exiting program..")

}

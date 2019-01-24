package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/elf"
)

func main() {
	m := elf.NewModule("./nspid-ebpf.o")

	if err := m.Load(nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load program: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := m.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to close program: %v", err)
		}
	}()

	m.EnableTracepoint("tracepoint/raw_syscalls/sys_enter")

	sig := make(chan os.Signal, 1)
	stopCh := make(chan struct{})

	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		for {
			select {
			case <-stopCh:
				return
			}
		}
	}()
	<-sig
}

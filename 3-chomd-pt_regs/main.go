package main

import (
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

/*
#include <linux/types.h>
struct data_t {
	__u32 pid;
	char file_name[256];
    __u32 mode;
};
*/
import "C"

type Event struct {
	Pid      uint32
	FileName string
	Mode     uint32
}

func main() {
	mod := elf.NewModule("bpf.o")
	err := mod.Load(nil)
	if err != nil {
		panic(err)
	}
	defer mod.Close()
	err = mod.EnableKprobes(128)
	if err != nil {
		panic(err)
	}

	channel := make(chan []byte)
	lost := make(chan uint64)

	perfMap, err := elf.InitPerfMap(mod, "fchmodat_event", channel, lost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}
	go func() {
		for {
			l := <-lost
			fmt.Println(l)
		}
	}()
	perfMap.PollStart()
	defer perfMap.PollStop()

	for {
		var event Event
		data := <-channel
		event = openEventToGo(&data)
		fmt.Printf("pid %d call fchmodat(fielname: %s, mode: %04s) \n", event.Pid,
			event.FileName, strconv.FormatUint(uint64(event.Mode), 8))
	}
}

func openEventToGo(data *[]byte) (event Event) {
	eventC := (*C.struct_data_t)(unsafe.Pointer(&(*data)[0]))

	event.Pid = uint32(eventC.pid)
	event.FileName = C.GoString(&eventC.file_name[0])
	event.Mode = uint32(eventC.mode)

	return
}

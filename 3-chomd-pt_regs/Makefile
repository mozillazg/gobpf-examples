all: bpf.o

clean:
	rm -f *~
	rm -f *.ll
	rm -f *.o

bpf.o: bpf.c clean
	@echo "Building Probe..."
	clang -O2 -emit-llvm -I../ -c bpf.c -o bpf.ll
	llc -march=bpf -filetype=obj -o bpf.o bpf.ll
	go build main.go

run:
	echo "" |sudo tee /sys/kernel/debug/tracing/kprobe_events
	sudo ./main

all: hello.o

clean:
	rm -f *~
	rm -f hello.ll
	rm -f hello.o

hello.o: hello.c clean
	@echo "Building Probe..."
	clang -O2 -emit-llvm -I../ -c hello.c -o hello.ll
	llc -march=bpf -filetype=obj -o hello.o hello.ll
	go build main.go

run:
	echo "" |sudo tee /sys/kernel/debug/tracing/kprobe_events
	sudo ./main

all: hello.o

hello.o: hello.c clean
	@echo "Building Probe..."
	clang -O2 -emit-llvm -I/kernel-src/tools/testing/selftests/bpf -c hello.c -o hello.ll
	llc -march=bpf -filetype=obj -o hello.o hello.ll

clean:
	rm -f *~
	rm -f hello.ll
	rm -f hello.o

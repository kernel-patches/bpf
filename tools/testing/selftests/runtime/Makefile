targets = simple branch loop

all: $(targets)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

%.bpf.o: %.bpf.c vmlinux.h
	clang -O2 -g -target bpf -c $*.bpf.c -o $*.bpf.o

%.skel.h: %.bpf.o
	bpftool gen skeleton $*.bpf.o > $*.skel.h

$(targets): %: %.c %.skel.h
	clang $< -lelf -lbpf -o $@

clean:
	rm -f *.o *.skel.h vmlinux.h $(targets)

.SECONDARY:

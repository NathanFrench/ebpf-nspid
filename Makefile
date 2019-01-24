always += nspid-ebpf.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KERNELDIR) M=$$PWD

clean:
	$(MAKE) -C $(KERNELDIR) M=$$PWD clean

$(obj)/nspid-ebpf.o: $(src)/nspid.c
	    clang $(LINUXINCLUDE) $(KBUILD_CPPFLAGS) $(DEBUG) -D__KERNEL__ -D__BPF_TRACING__ -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -fno-jump-tables -Wno-tautological-compare -O2 -g -emit-llvm -c $< -o $(patsubst %.o,%.ll,$@)
	llc -march=bpf -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)




PPC_CFLAGS := -O3 -static -fomit-frame-pointer -fno-exceptions \
		-fno-asynchronous-unwind-tables -fno-unwind-tables \
		-fno-stack-protector -ffreestanding -nostdlib \
		-ffunction-sections -fdata-sections -Wl,--gc-sections
X86_CFLAGS := -O3 -static -fomit-frame-pointer -fno-exceptions \
		-fno-asynchronous-unwind-tables -fno-unwind-tables \
		-fno-stack-protector -ffreestanding -nostdlib \
		-ffunction-sections -fdata-sections -Wl,--gc-sections
X86DBG_CFLAGS := -g -O0 -fno-inline -fsanitize=address

PPC_NANOLIBC := libc/libc.c libc/printf.c libc/_start.s
X86_NANOLIBC := libc/libc.c libc/printf.c libc/_start.x86_64.s


.PHONY: all clean

all: ppcinterp demo/args

clean:
	rm ppcinterp demo/args

ppcinterp: ppcinterp.c libc/nanolibc.h $(X86_NANOLIBC)
	gcc -DNANOLIBC $(X86_CFLAGS) -Ilibc -o ppcinterp ppcinterp.c $(X86_NANOLIBC)

demo/args: demo/args.c libc/nanolibc.h $(PPC_NANOLIBC)
	powerpc-linux-gnu-gcc -DNANOLIBC $(PPC_CFLAGS) -Ilibc -o demo/args demo/args.c $(PPC_NANOLIBC)

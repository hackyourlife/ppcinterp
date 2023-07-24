ppcinterp
=========

This is a minimalistic interpreter for a subset of the PowerISA 2.07 in 32bit
mode which can run some small test programs. This interpreter does not use any
libc or dynamic linking and directly interacts with Linux syscalls instead.

It provides a minimal set of Linux syscalls to the guest program, but it cannot
run glibc based programs at the moment due to various missing features (e.g.,
`sbrk` is not emulated).


System Requirements
-------------------

- Linux (AMD64 or PPC)
- GCC
- Make


Security
--------

This interpreter is completely insecure since all memory accesses of the guest
program are directly performed without any filtering or translation beyond
adding an offset.

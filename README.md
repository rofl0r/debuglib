debuglib - a convenience wrapper around ptrace
==============================================

this library tries to abstract away arch-specific differences for ptrace(),
and provide a neater, consistent high-level interface.

- provides facilities to set breakpoints,
- execute till breakpoint,
- single-step processes,
- read and write from process memory,
- hook syscalls and read and modify syscall arguments

it was written with the idea of writing a custom ncurses debugger without
having to remote-control gdb. using the provided primitives it is quite
easy to write an asm-level debugger like ollydbg, but for a source-
based debugger like gdb it is required to deal with the different DWARF
formats, which are quite complicated.

the API is unstable at this moment.
there are working examples for a debugger and syscall hooks in the
tests/ directory.

debuglib was designed for use with the
[RcB2](https://github.com/rofl0r/rcb2) build tool, and depends on my
multi-purpose C library [libulz](https://github.com/rofl0r/libulz),
which provides some data structures such as hashmaps and lists.

How to build the filetracer example program
-------------------------------------------

	cd /tmp
	mkdir debuglib-0000
	cd debuglib-0000/
	git clone https://github.com/rofl0r/debuglib
	git clone https://github.com/rofl0r/libulz lib
	git clone https://github.com/rofl0r/rcb2
	export PATH=$PATH:/tmp/debuglib-0000/rcb2
	ln -s /tmp/debuglib-0000/rcb2/rcb2.py /tmp/debuglib-0000/rcb2/rcb2
	cd debuglib/tests
	rcb2 filetrace.c


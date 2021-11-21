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

Known bugs:
-----------
there are 2 ways to use the ptrace(2) api: the old method is using
`PTRACE_ATTACH`, this is what the library currently uses.
it has one major problem, which is the inability to properly deal with
`SIGSTOP`/`SIGTSTP` received by a child when tracing.
therefore a new API was designed that uses `PTRACE_SEIZE` instead.
i was unaware of the issue when designing this library and using the new
seize API instead would require a major rewrite, and more costly, re-test
of all the functionality.
fortunately processes sending SIGSTOP to subprocesses occur quite rarely,
so the issue is encountered only in rare cases.
the issue can be reproduced by creating a shell script with the content

    msgmerge --update -q /dev/null /dev/null

on debian sid i386 at the time of this writing, and then executing

    DEBUG=1 idfake sh foo.sh

using the supplied idfake example program.
This result in the program hanging forever.
the rather well-known program `proot` is victim to the same design issue.
recent versions of `strace` otoh use the new seize API when available.

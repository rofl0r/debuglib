#ifndef SYSCALLS_H
#define SYSCALLS_H

const char* syscall_get_name(unsigned sc);
unsigned syscall_get_argcount(unsigned sc);

#pragma RcB2 DEP "syscalls.c"

#endif

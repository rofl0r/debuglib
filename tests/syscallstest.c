#include "../syscalls.h"
#include <stdio.h>
#include <sys/syscall.h>

#define test SYS_fanotify_init
//#define test 4340
int main() {
	dprintf(2, "%s : %d\n",
		syscall_get_name(test),
		syscall_get_argcount(test) );

}

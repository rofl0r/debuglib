#include "../debuglib.h"
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include "../syscalls.h"

extern char** environ;

static int debugmode;
#define vprintf(...) do { if(debugmode) dprintf(__VA_ARGS__); } while(0)

int main(int argc, char** argv) {
	(void) argc;
	debugmode = getenv("DEBUG") != 0;
	pid_t child;
	int retval;
	debugger_state dbga, *d = &dbga;
	debugger_event de;
	
	size_t childcount = 1;
	size_t c;
	
	debugger_state_init(d);
	
	if((c = debugger_exec(d, argv[1], &argv[1], environ)) == (size_t) -1) {
		dprintf(2, "failed to launch debuggee\n");
		return 1;
	}
	
	dprintf(2, "child pid %d\n", debugger_pid_from_pidindex(d, c));
	if(!debugger_wait_syscall(d, c)) return 1;
	
	while(1) {
		size_t childs_alive = 0;
		for (c = 0; c < childcount; c++) {
			child = debugger_pid_from_pidindex(d, c);
			if(child == -1) continue;
			childs_alive++;
			de = debugger_get_events(d, c, &retval, 0);
			if(de != DE_NONE) {
				vprintf(2, "DE: %s\n", debugger_get_event_name(de));
				if(de == DE_SYSCALL_ENTER || de == DE_SYSCALL_RETURN) {
					long sc = debugger_get_syscall_number(d, c);
					vprintf(2, "syscall: %s (#%ld) (proc %zu)\n", syscall_get_name(sc), sc, c);
					if(de == DE_SYSCALL_ENTER &&
						sc == SYS_mmap 
#if defined SYS_mmap2
						|| sc == SYS_mmap2
#endif
					) {
						//debugger_set_syscall_number(d, child, SYS_exit);
						int i = 1;
						for(; i < 7; i++) {
							long arg = debugger_get_syscall_arg(d, c, i);
							vprintf(2, "arg %d : %p\n", i, (void*) arg);
							if(i == 4) debugger_set_syscall_arg(d, c, 4, arg | MAP_32BIT);
						}
					}
					if(!debugger_wait_syscall(d, c)) return 1;
				} else if (de == DE_EXIT) {
					dprintf(2, "got de_exit from %zu, return val %d\n", c, retval);
					debugger_continue(d, c);
					debugger_set_pid(d, c, -1);
					continue;
				} else if (de == DE_CLONE) {
					debugger_add_pid(d, retval);
					childcount = debugger_get_pidcount(d);
					dprintf(2, "got clone, childcount: %zu, lwp pid = %d\n", childcount, retval);
					usleep(1); /* we need to sleep for a tiny amount, otherwise PTRACE_SYSCALL
					              will fail with "no such process" */
					if(!debugger_wait_syscall(d, childcount - 1)) return 1;
					//usleep(1);
					if(!debugger_wait_syscall(d, c)) return 1;
				}
			}
		}
		if(!childs_alive) return 0;
		usleep(1);
	}
	
}
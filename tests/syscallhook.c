#include "../debuglib.h"
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/mman.h>

extern char** environ;

int main(int argc, char** argv) {
	pid_t child;
	int retval;
	debugger_state dbga, *d = &dbga;
	debugger_event de;
	void* addr;
	
#define MAX_CHILDS 256 /* max number of threads including main one */
	
	pid_t childs[MAX_CHILDS];
	size_t childcount = 1;
	
	debugger_state_init(d);
	
	if((childs[0] = start_debuggee(argv[1], &argv[1], environ)) == (pid_t) -1) {
		dprintf(2, "failed to launch debuggee\n");
		return 1;
	}
	
	dprintf(2, "child pid %d\n", childs[0]);
	if(!debugger_wait_syscall(d, childs[0])) return 1;
	
	while(1) {
		size_t c;
		size_t childs_alive = 0;
		for (c = 0; c < childcount; c++) {
			child = childs[c];
			if(child == -1) continue;
			childs_alive++;
			de = debugger_get_events(d, child, &retval, 0);
			if(de != DE_NONE) {
				dprintf(2, "DE: %s\n", debugger_get_event_name(de));
				if(de == DE_SYSCALL_ENTER || de == DE_SYSCALL_RETURN) {
					long sc = debugger_get_syscall_number(d, child);
					dprintf(2, "sc: %ld\n", sc);
					if(sc == SYS_mmap 
	#if defined SYS_mmap2
						|| sc == SYS_mmap2
	#endif
					) {
						//debugger_set_syscall_number(d, child, SYS_exit);
						int i = 1;
						for(; i < 7; i++) {
							long arg = debugger_get_syscall_arg(d, child, i);
							dprintf(2, "arg %d : %p\n", i, arg);
							if(i == 4) debugger_set_syscall_arg(d, child, 4, arg | MAP_32BIT);
						}
						
					}
					if(!debugger_wait_syscall(d, child)) return 1;
				} else if (de == DE_EXIT) {
					childs[c] = -1;
				} else if (de == DE_CLONE) {
					childs[childcount++] = retval;
					debugger_continue(d, retval);
					debugger_continue(d, child);
				}
			}
		}
		if(!childs_alive) return 0;
		usleep(1);
	}
	
}
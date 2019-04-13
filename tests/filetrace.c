#include "../debuglib.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include "../syscalls.h"

extern char** environ;

static int debugmode;
#define vprintf(...) do { if(debugmode) dprintf(__VA_ARGS__); } while(0)

static int usage(const char *a0) {
	dprintf(2, "usage: %s filename.log command [args...]\n"
		   "runs command with args...\n"
		   "logs all SYS_open syscall filenames to filename.log\n"
		   "filename.log may be '-', which means stdout\n"
		   , a0);
	return 1;
}

static int search_path_bin(const char *bin, char *buf, size_t buflen) {
	char *p = getenv("PATH"), *tok = strtok(p, ":");
	if (tok) do {
		snprintf(buf, buflen, "%s/%s", tok, bin);
		if(access(buf, X_OK) == 0) return 1;
	} while((tok = strtok(NULL, ":")));
	return 0;
}

static int read_process_string(pid_t pid, char *buf, size_t bufsize, uintptr_t source_addr)
{
	while(bufsize > 1) {
		if(!read_process_memory_slow(pid, buf, source_addr++, 1))
			return 0;
		if(*buf == 0) return 1; /* success */
		buf++;
		bufsize--;
	}
	*buf = 0;
	return -1; /* string truncated */
}

struct waiter {
	pid_t waiter;
	pid_t child;
};

static int child_of(pid_t parent, pid_t childspec, pid_t child)
{
	if(childspec != -1 && child != childspec) return 0;
	char procbuf[256];
	snprintf(procbuf, sizeof procbuf, "/proc/%d/status", (int) child);
	FILE *f = fopen(procbuf, "r");
	while(fgets(procbuf, sizeof procbuf, f)) {
		if(!strncmp(procbuf, "PPid:", 5)) {
			fclose(f);
			int ppid = atoi(procbuf+5);
			if(ppid == parent) return 1;
			return 0;
		}
	}
	abort();
}

int main(int argc, char** argv) {
	if (argc < 3) return usage(argv[0]);
	FILE *f = stdout;
	if(strcmp(argv[1], "-")) {
		if(access(argv[1], X_OK) == 0) {
			dprintf(2, "error: file %s exists and is executable\n"
				   "aborting to prevent accidental overwrite of a binary\n"
				   , argv[1]);
			return 1;
		}
		f = fopen(argv[1], "w");
		if(!f) {
			dprintf(2, "error: could not open %s in write mode\n"
				   , argv[1]);
			return 1;
		}
	}
	char progbuf[256];
	snprintf(progbuf, sizeof progbuf, "%s", argv[2]);
	if(access(progbuf, X_OK) && !search_path_bin(argv[2], progbuf, sizeof progbuf)) {
		dprintf(2, "could not find executable %s\n", argv[2]);
		return 1;
	}
	debugmode = getenv("DEBUG") != 0;
	pid_t child;
	int retval;
	debugger_state dbga, *d = &dbga;
	debugger_event de;
	sblist *waiters = sblist_new(sizeof (struct waiter), 8);

	size_t childcount = 1;
	size_t c;

	debugger_state_init(d);

	if((c = debugger_exec(d, progbuf, &argv[2], environ)) == (size_t) -1) {
		dprintf(2, "failed to launch debuggee\n");
		return 1;
	}

	vprintf(2, "child pid %d\n", debugger_pid_from_pidindex(d, c));
	if(!debugger_wait_syscall(d, c)) return 1;

	while(1) {
mainloop:;
		size_t childs_alive = 0;
		for (c = 0; c < childcount; c++) {
			child = debugger_pid_from_pidindex(d, c);
			if(child == -1) continue;
			childs_alive++;
			de = debugger_get_events(d, c, &retval, 0);
			if(de != DE_NONE) {
				if(!(de == DE_SYSCALL_ENTER || de == DE_SYSCALL_RETURN))
					vprintf(2, "DE: %s\n", debugger_get_event_name(de));
				if(de == DE_SYSCALL_ENTER || de == DE_SYSCALL_RETURN) {
					long sc = debugger_get_syscall_number(d, c);
					int skip_wait = 0;
					vprintf(2, "[%.5d] %s: %s (#%ld) (proc %zu)\n", child, de == DE_SYSCALL_ENTER ? "ENTER" : "RETURN", syscall_get_name(sc), sc, c);
					if(debugmode &&
						de == DE_SYSCALL_ENTER &&
						sc == SYS_open ||
						sc == SYS_wait4
					) {
						/* interesting syscalls */
						int i;
						for(i = 1; i <= syscall_get_argcount(sc); i++) {
							long arg = debugger_get_syscall_arg(d, c, i);
							vprintf(2, "arg %d : %p\n", i, (void*) arg);
						}
					}
					if(de == DE_SYSCALL_ENTER) switch(sc) {
						case SYS_open: {
							char fnbuf[512];
							read_process_string(child, fnbuf, sizeof fnbuf, debugger_get_syscall_arg(d, c, 1));
							fprintf(f, "%s\n", fnbuf);
						} break;
						case SYS_wait4: {
							struct waiter w = {
								.waiter = child,
								.child = debugger_get_syscall_arg(d, c, 1),
							};
							sblist_add(waiters, &w);
							skip_wait = 1;
							debugger_continue(d, c);
						} break;
					}
					if(!skip_wait) {
						if(!debugger_wait_syscall(d, c)) return 1;
					}
				} else if (de == DE_EXIT || de == DE_VFORK_DONE) {
					vprintf(2, "got de_exit from %zu, return val %d\n", c, retval);
					debugger_continue(d, c);
					//debugger_detach(d, c);
					debugger_set_pid(d, c, -1);
					size_t iter;
					for(iter = 0; iter < sblist_getsize(waiters); ) {
						struct waiter *w = sblist_get(waiters, iter);
						if(w->waiter == child) {
							sblist_delete(waiters, iter);
						} else if(child_of(w->waiter, w->child, child)) {
							sblist_delete(waiters, iter);
							ssize_t pid_index = debugger_pidindex_from_pid(d, w->waiter);
							if(pid_index != -1) {
								//kill(w->waiter, SIGCHLD);
								//kill(w->waiter, SIGTRAP);
								//ptrace(PTRACE_restart, w->waiter, 0, 0);
								//usleep(100);
								//debugger_wait_syscall(d, pid_index);
								//debugger_wait_syscall(d, pid_index);
							}
						} else iter++;
					}
					goto mainloop;
				} else if (de == DE_CLONE || de == DE_VFORK || de == DE_FORK) {
					//debugger_attach(d, retval);
					debugger_add_pid(d, retval);
					childcount = debugger_get_pidcount(d);
					vprintf(2, "got clone, childcount: %zu, lwp pid = %d\n", childcount, retval);
					do {
						usleep(10); /* we need to sleep for a tiny amount, otherwise PTRACE_SYSCALL
					              will fail with "no such process" */
						if(!debugger_wait_syscall(d, childcount - 1)) {
							if(errno != ESRCH) return 1;
						} else break;
					} while(errno == ESRCH);
					//usleep(1);
					if(!debugger_wait_syscall(d, c)) return 1;
				} else if (de == DE_EXEC) {
					vprintf(2, "got exec from child #%zu (pid: %d), pid %d\n", c, child, retval);
					do {
						usleep(10);
						if(!debugger_wait_syscall(d, c)) {
							dprintf(2, "unexpected\n");
							if (errno != ESRCH) return 1;
						} else break;
					} while(errno == ESRCH);
					//if(!debugger_wait_syscall(d, debugger_pidindex_from_pid(d, retval))) return 1;
					//debugger_continue(d, c);
				}
			}
		}
		if(!childs_alive) break;
		usleep(1);
	}
	if(f != stdout) fclose(f);
	return 0;
}

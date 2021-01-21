/*

this program hooks syscalls
SYS_setgroups, SYS_setresgid, SYS_setresuid, and SYS_chown.

since we can't just stop an entered syscall from executing,
we modify the syscall nr to something inexistent, in this
the syscall we received negated. this allows us to detect
when we return which syscall was used, even though it is
not necessary in this example.
when the syscall returns, we modify the return value to
return 0 (success).

this was meant to make "apt update" work in fakeroot-style
ubuntu rootfs with limited privileges, and rather than
just failing on a potential permission error e.g. when trying
to write to the file system, all sorts of stupid checks are
being done instead, and those fail because the pseudo-root
user doesn't have permissions to e.g. change the owner of
files.
by using this ptrace hack, i got around the initial errors,
but got a new error message which led me to the right spot
in the apt source so i was able to figure out how to work
around it without a hack: simply remove the _apt user from
/etc/passwd.


*/

#include "../debuglib.h"
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include "../syscalls.h"
#include "../signals.h"

extern char** environ;

static int search_path_bin(const char *bin, char *buf, size_t buflen) {
	char *p = getenv("PATH"), *o;
	size_t l;
	for(;;) {
		o = buf;
		l = buflen;
		while(l && *p && *p != ':') {
			*(o++) = *(p++);
			l--;
		}
		snprintf(o, l, "/%s", bin);
		if(access(buf, X_OK) == 0) return 1;
		if(*p == ':') p++;
		else if(!p) break;
	}
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

static int debugmode;
#define vprintf(...) do { if(debugmode) dprintf(__VA_ARGS__); } while(0)

int main(int argc, char* argv[]) {
	assert (argc > 1);
	char progbuf[256];
	int progname_arg = 1;
	snprintf(progbuf, sizeof progbuf, "%s", argv[progname_arg]);
	if(access(progbuf, X_OK) && !search_path_bin(argv[progname_arg], progbuf, sizeof progbuf)) {
		dprintf(2, "could not find executable %s\n", argv[progname_arg]);
		return 1;
	}

	debugmode = getenv("DEBUG") != 0;
	pid_t child;
	int retval;
	debugger_state dbga, *d = &dbga;
	debugger_event de;

	debugger_state_init(d);

	argv[progname_arg] = progbuf;

	if((child = debugger_exec(d, progbuf, argv+progname_arg, environ)) == (size_t) -1) {
		dprintf(2, "failed to launch debuggee\n");
		return 1;
	}

	vprintf(2, "child pid %d\n",  child);
	if(!debugger_wait_syscall(d, child, 0)) return 1;

	int blocking_io = 1;
	size_t childs_alive;

	while((childs_alive = debugger_get_pidcount(d))) {
		if(!blocking_io) usleep(10);
		child = -1; /* set pid to -1 so all childs are queried */
		de = debugger_get_events(d, &child, &retval, blocking_io);
		assert(child != -1);
		switch(de) {
		case DE_NONE:
			if(!blocking_io) usleep(100000);
			break;
		case DE_SIGNAL:
			vprintf(2, "[%.5d] DE: %s [%d -> %s]\n", child, debugger_get_event_name(de), retval, get_signal_name(retval));
			debugger_wait_syscall(d, child, retval);
			break;
		case DE_VFORK_DONE:
			vprintf(2, "got vfork_done, from %d, ret %d\n", child, retval);
			if(!debugger_wait_syscall(d, child, 0)) return 1;
			break;

		case DE_EXIT:
			vprintf(2, "got %s from %d, return val %d, exit status %d\n", debugger_get_event_name(de), (int) child, retval, WEXITSTATUS(retval));
			debugger_continue(d, child);
			debugger_remove_pid(d, child);
			break;
		case DE_CLONE: case DE_VFORK: case DE_FORK:
			debugger_add_pid(d, retval);
			childs_alive = debugger_get_pidcount(d);
			vprintf(2, "got clone, childcount: %zu, lwp pid = %d\n", childs_alive, retval);
			if(!debugger_wait_syscall_retry(d, retval, 0)) {
				dprintf(2, "unexpected\n");
				return 1;
			}
			if(!debugger_wait_syscall(d, child, 0)) return 1;
			break;
		case DE_EXEC:
			vprintf(2, "got exec from child (pid: %d), pid %d\n", child, retval);
			if(!debugger_wait_syscall_retry(d, child, 0)) {
				dprintf(2, "unexpected\n");
				return 1;
			}
			break;

		case DE_SYSCALL_ENTER: case DE_SYSCALL_RETURN: {
			long sc = debugger_get_syscall_number(d, child);
			vprintf(2, "[%.5d] %s: %s (#%ld)\n", child, de == DE_SYSCALL_ENTER ? "ENTER" : "RETURN", syscall_get_name(sc), sc);
			int i;
			for(i = 1; i <= syscall_get_argcount(sc); i++) {
				long arg = debugger_get_syscall_arg(d, child, i);
				vprintf(2, "arg %d : %p\n", i, (void*) arg);
			}

			if(de == DE_SYSCALL_ENTER) switch (sc) {
				case SYS_setgroups:
				case SYS_setresgid:
				case SYS_setresuid:
				case SYS_chown:
				debugger_set_syscall_number(d, child, -sc);
				break;
			}

			if(de == DE_SYSCALL_RETURN) switch(sc) {
				case -SYS_setgroups:
				case -SYS_setresgid:
				case -SYS_setresuid:
				case -SYS_chown:
				debugger_set_syscall_ret(d, child, 0);
				break;
			}

			if(de == DE_SYSCALL_ENTER && sc == SYS_execve) {
				char path[512];
				read_process_string(child, path, sizeof path, debugger_get_syscall_arg(d, child, 1));
				vprintf(2, "%s: %s\n", syscall_get_name(sc), path);
			}

			if(!debugger_wait_syscall(d, child, 0)) return 1;
		}
		break;
		}
	}

	return 0;
}

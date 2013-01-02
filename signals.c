#include <signal.h>
#include "../lib/include/macros.h"

const char* signal_names[] = {
        [SIGHUP] = "SIGHUP",
        [SIGINT] = "SIGINT",
        [SIGQUIT] = "SIGQUIT",
        [SIGILL] = "SIGILL",
        [SIGTRAP] = "SIGTRAP",
        [SIGABRT] = "SIGABRT",
        [SIGBUS] = "SIGBUS",
        [SIGFPE] = "SIGFPE",
        [SIGKILL] = "SIGKILL",
        [SIGUSR1] = "SIGUSR1",
        [SIGSEGV] = "SIGSEGV",
        [SIGUSR2] = "SIGUSR2",
        [SIGPIPE] = "SIGPIPE",
        [SIGALRM] = "SIGALRM",
        [SIGTERM] = "SIGTERM",
        [SIGSTKFLT] = "SIGSTKFLT",
        [SIGCHLD] = "SIGCHLD",
        [SIGCONT] = "SIGCONT",
        [SIGSTOP] = "SIGSTOP",
        [SIGTSTP] = "SIGTSTP",
        [SIGTTIN] = "SIGTTIN",
        [SIGTTOU] = "SIGTTOU",
        [SIGURG] = "SIGURG",
        [SIGXCPU] = "SIGXCPU",
        [SIGXFSZ] = "SIGXFSZ",
        [SIGVTALRM] = "SIGVTALRM",
        [SIGPROF] = "SIGPROF",
        [SIGWINCH] = "SIGWINCH",
#if SIGIO != SIGPOLL
        [SIGIO] = "SIGIO",
#endif
        [SIGPOLL] = "SIGPOLL",
        [SIGPWR] = "SIGPWR",
        [SIGSYS] = "SIGSYS",
};

const char* get_signal_name(int sig) {
	if(sig >= 0 && (unsigned) sig < ARRAY_SIZE(signal_names))
		return signal_names[sig];
	return "unknown signal";
}
#include "../debuglib.h"
#include "../signals.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>

extern char** environ;


ssize_t gets_nonblocking(int fd, char* buf, size_t bufsize) {
	struct timeval tv = {0, 1000};
	int ret;
	fd_set readfds;
	ssize_t nread = 0;
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	if((ret = select(fd + 1, &readfds, NULL, NULL, &tv)) == -1) {
		perror("select");
		return -1;
	} else if (ret > 0) {
		nread = read(fd, buf, bufsize);
	}
	return nread;
}

int main(int argc, char** argv) {
	ssize_t nread;
	char linebuf[160];
	pid_t child;
	int retval;
	debugger_state dbga;
	debugger_event de;
	uintptr_t addr;

	debugger_state_init(&dbga);

	if((child = debugger_exec(&dbga, argv[1], &argv[1], environ)) == (pid_t) -1) {
		puts("failed to launch debuggee");
		return 1;
	}
	int last_command = 0;
	while(1) {
		nread = gets_nonblocking(0, linebuf, sizeof(linebuf));
		if(nread) {
	eval_cmd:;
			switch(linebuf[0]) {
				case 'b':
					addr = strtol(&linebuf[2], NULL, 16);
					dprintf(2, "setting breakpoint on %p\n", addr);
					debugger_set_breakpoint(&dbga, child, addr);
					break;
				case 'c':
					debugger_continue(&dbga, child);
					last_command = linebuf[0];
					break;
				case 's':
					debugger_single_step(&dbga, child);
					last_command = linebuf[0];
					break;
				case '\n':
					if(last_command) {
						linebuf[0] = last_command;
						goto eval_cmd;
					}
					/* fall-through */
				default:
					puts("unknown prefix");

			}
			last_command = linebuf[0];
		}
		if((de = debugger_get_events(&dbga, &child, &retval, 0)) != DE_NONE) {
			printf("got a debugger event, retval %d, (%s)\n", retval, debugger_get_event_name(de));
			switch(de) {
			case DE_EXIT:
				puts("child exited.");
				return 0;
			case DE_SIGNAL:
				dprintf(2, "[%.5d] DE: %s [%d -> %s]\n", child, debugger_get_event_name(de), retval, get_signal_name(retval));
				break;
			}
		}

		sleep(1);
	}

	return 0;
}

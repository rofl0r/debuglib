#include "../debuglib.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
	void* addr;
	
	debugger_state_init(&dbga);
	
	if((child = start_debuggee(argv[1], &argv[1], environ)) == (pid_t) -1) {
		puts("failed to launch debuggee");
		return 1;
	}
	while(1) {
		nread = gets_nonblocking(0, linebuf, sizeof(linebuf));
		if(nread) {
			switch(linebuf[0]) {
				case 'b': 
					addr = (void*) strtol(&linebuf[2], NULL, 16);
					debugger_set_breakpoint(&dbga, child, addr);
					break;
				case 'c':
					debugger_continue(&dbga, child);
					break;
				case 's':
					debugger_single_step(&dbga, child);
					break;
					
				default:
					puts("unknown prefix");
				
			}
		}
		if((de = debugger_get_events(&dbga, child, &retval, 0)) != DE_NONE) {
			printf("got a debugger event, retval %d\n", retval);
			if(de == DE_EXIT) {
				puts("child exited.");
				return 0;
			}
		}

		sleep(1);
	}
	
	return 0;
}

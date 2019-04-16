#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char** argv) {
	if(argc == 1) {
		puts("vforking child...");
		pid_t child = vfork();
		if(!child) {
			char buf[512];
			snprintf(buf, sizeof buf, "%s child | cat", argv[0]);
			execlp("/bin/sh", "/bin/sh", "-c", buf, (char*) 0);
			puts("oops");
			_exit(1);
		} else {
			int status;
			wait(&status);
		}
	} else {
		puts("called from child");
		sleep(1);
	}
	return 0;
}

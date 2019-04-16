#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char** argv) {
	if(argc == 1) {
		puts("forking child...");
		pid_t child = fork();
		if(!child) {
			execl(argv[0], argv[0], "child", (char*) 0);
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

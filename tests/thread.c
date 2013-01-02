#include <pthread.h>
#include <unistd.h>

void* threadfunc(void* x) {
	while(1) {
		sleep(1);
		write(2, "y", 1);
	}
	return 0;
}

int main(int argc, char **argv) {
	pthread_t t;
	pthread_create(&t, 0, threadfunc, 0);
	while(1) {
		write(1, "x", 1);
		sleep(1);
	}
}
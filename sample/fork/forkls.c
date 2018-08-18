#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main() {
	pid_t child;
	int status;
	child = fork();
	if (child == -1) {
		perror("fork");
        exit(EXIT_FAILURE);
	}
	if (!child) {
		system("ls -L");
	}
	if (child) {
		waitpid(child, &status, 0);
	}
	return 0;
}
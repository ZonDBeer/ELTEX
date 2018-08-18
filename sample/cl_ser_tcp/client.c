#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BUFFLEN 200

int getrand(int min, int max) {
    return (double)rand() / (RAND_MAX + 1.0) * (max - min) + min;
}

double wtime() {
    struct timeval t;
    gettimeofday(&t, NULL);
    return (double)t.tv_sec + (double)t.tv_usec * 1E-6;
}

void _rand_string(int *length, char *string) {
	length = getrand(10, 25);
	for (int i = 0; i < length; ++i) {
		string[i] = getrand(50, 100);
	}
}

int main (int argc, char **argv) {
	int c_socket, length_msg;
	char buffer[BUFFLEN];
	struct sockaddr_in addr;

	srand(wtime(NULL));

	printf("%s", "init net...");
	if ((c_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("[fail] - e1");
		exit(1);
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(argv[1]);
	addr.sin_port = htons(atoi(argv[2]));
	if (connect(c_socket, &addr, sizeof(addr)) < 0) {
		perror("[fail] - e2");
		exit(1);
	}
	printf("%s\n", "[done]");

	bzero(buffer, BUFFLEN);
	_rand_string(&length_msg, buffer);
	printf("string: %s\n", buffer);

	printf("%s", "send string...");
	if (send(c_socket, buffer, strlen(buffer), NULL) < 0) {
		perror("[fail] - e3");
		exit(1);
	}
	printf("%s\n", "[done]");

	bzero(buffer, BUFFLEN);
	printf("%s", "getting answer...");
	if (recv(c_socket, buffer, BUFFLEN, NULL) < 0) {
		perror("[fail] - e4");
		exit(1);
	}
	printf("%s\n", "[done]");
	printf("answer: %s\n", buffer);
	close(c_socket);
}
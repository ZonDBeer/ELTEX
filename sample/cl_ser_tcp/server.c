#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFLEN 200

void _string_reverse(char *string) {
	int length = strlen(string);
	char tmp;
	for (int i = 0; i < (length / 2); ++i) {
		tmp = string[i];
		string[i] = string[length - i - 1];
		string[length - i - 1] = tmp;
	}
}

int main(int argc, char **argv) {
	int s_socket, c_socket, length_addr, length_msg;
	char buffer[BUFFLEN];
	struct sockaddr_in servAddr;

	printf("%s", "start server...");
	s_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (s_socket < 0) {
		perror("[fail] - e1\n");
		exit (1);
	}
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servAddr.sin_port = 0;
	if (bind(s_socket, &servAddr, sizeof(servAddr))) {
		perror("[fail] - e2\n");
		exit(1);
	}

	length_addr = sizeof(servAddr);
	if (getsockname(s_socket, &servAddr, &length_addr)) {
		perror("[fail] - e3\n");
		exit(1);
	}
	if (listen(s_socket, 5) < 0) {
		perror("[fail] - e4\n");
		exit(1);
	}
	printf("[done]\nserver port: %d\n", ntohs(servAddr.sin_port));
	printf("server ip: %s\n", inet_ntoa(servAddr.sin_addr));
	printf("waiting...\n");
	for ( ; ; ) {
		if ((c_socket = accept(s_socket, 0, 0)) < 0) {
			perror ("[fail] - e5\n");
			exit(1);
		}
		
		bzero(buffer, BUFFLEN);
		if ((length_msg = recv(c_socket, buffer, BUFFLEN, NULL)) < 0) {
			perror ("[fail] - e6\n");
			exit(1);
		}
		printf("msg: %s\n", buffer);
		_string_reverse(buffer);
		if (send(c_socket, buffer, strlen(buffer), NULL) < 0) {
			perror("[fail] - e7\n");
			exit(1);
		}
	}
	close(s_socket);
}
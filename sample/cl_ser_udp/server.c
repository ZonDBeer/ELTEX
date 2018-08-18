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
	int s_socket, length_addr, length_msg;
	char buffer[BUFFLEN];
	struct sockaddr_in servAddr, clientAddr;

	printf("%s", "start server...");
	s_socket = socket(AF_INET, SOCK_DGRAM, 0);
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
	printf("[done]\nserver port: %d\n", ntohs(servAddr.sin_port));
	printf("server ip: %s\n", inet_ntoa(servAddr.sin_addr));
	printf("waiting...\n");
	for ( ; ; ) {
		length_addr = sizeof(clientAddr);
		bzero(buffer, BUFFLEN);
		if ((length_msg = recvfrom(s_socket, buffer, BUFFLEN, NULL,
			&clientAddr, &length_addr)) < 0) {
			perror ("[fail] - e4\n");
			exit(1);
		}
		printf("client ip: %s, ", inet_ntoa(clientAddr.sin_addr));
		printf("port: %d\n", clientAddr.sin_port);
		printf("msg: %s\n", buffer);
		_string_reverse(buffer);
		if (sendto(s_socket, buffer, strlen(buffer),
		 NULL, &clientAddr, sizeof(clientAddr)) < 0) {
			perror("[fail] - e5");
		exit(1);
		}
	}
	close(s_socket);
}
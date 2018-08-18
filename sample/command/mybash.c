#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // fork, vfork
#include <sys/types.h> // vfork
#include <string.h>

void _do(char *_command) {
	pid_t child;
	int status;
	char *pch;
	int fd[2];
	int _standart = dup(1);
	char _pars0[2][50] = {{'\0'}};
	char _pars1[2][50] = {{'\0'}};
	//strtok_r(_command, '|', _pars0);
	pch = strtok (_command, "|");
	int cc = 0;
  	while (pch != NULL) {
  		strncat(&_pars0[cc], pch, strlen(pch));
  		printf("tok0:%s\n", pch);
    	pch = strtok (NULL, "|");
    	++cc;
  	}

	for(int i = 0; i < cc; ++i) {
		//strtok_r(_pars0[i], ' ', _pars1);
		bzero(_pars1[0], 50);
		bzero(_pars1[1], 50);
		pch = strtok (_pars0[i], "_");
		strncat(&_pars1[0], pch, strlen(pch));
		pch = strtok (NULL, "_");
		strncat(&_pars1[1], pch, strlen(pch));

		if (i < cc - 1){
			pipe(&fd);
			dup2(fd[1], 1);
			//dup2(fd[1], 0);
		} else {
			dup2(_standart, 1);
		}
		child = fork();
		if (!child) {
			printf("tok1:%s\n", _pars1[0]);
			printf("tok1:%s\n", _pars1[1]);
			status = execlp(&_pars1[0], &_pars1[1], (char *) 0);
			printf("status: %d\n", status);
		}
		if (child == -1) {
			perror("fork");
        	exit(EXIT_FAILURE);
		}
		if (child) {
			waitpid(child, &status, 0);
		}
	}
}

int main() {
	char _command[1024];
	scanf("%s", _command);
	_do(_command);
	return 0;
}
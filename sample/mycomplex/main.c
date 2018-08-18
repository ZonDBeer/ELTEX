#include <stdio.h>
#include "mycomplex.h"
#include "mycomplex_add.h"
#include "mycomplex_sub.h"
#include "mycomplex_mul.h"
#include "mycomplex_div.h"

int main() {
	int chose;
	struct _mycomplex num1, num2, num3;
	while(1) {
		printf("Chose operation:\n[1] - addition\n[2] - subtract\n[3] - multiply\n[4] - division\n[5] - quit\n");
		scanf("%d", &chose);
		if (chose == 5) {
			break;
		}
		printf("Type real and imag for num1:");
		scanf("%lf %lf", &num1.real, &num1.imag);
		printf("Type real and imag for num2:");
		scanf("%lf %lf", &num2.real, &num2.imag);
		switch(chose) {
			case 1:
				num3 = _mycomplex_add(num1, num2);
				break;
			case 2:
				num3 = _mycomplex_sub(num1, num2);
				break;
			case 3:
				num3 = _mycomplex_mul(num1, num2);
				break;
			case 4:
				num3 = _mycomplex_div(num1, num2);
				break;
			default:
				printf("Wrong input.\n");
		}
		printf("Answer: %lf + %lfi\n", num3.real, num3.imag);
	}

	return 0;
}
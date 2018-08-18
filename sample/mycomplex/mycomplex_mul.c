#include "mycomplex.h"
#include "mycomplex_mul.h"
struct _mycomplex _mycomplex_mul(struct _mycomplex num1, struct _mycomplex num2) {
	struct _mycomplex num3;
	num3.real = num1.real*num2.real - num1.imag*num2.imag;
	num3.imag = num1.real*num2.imag + num1.imag*num2.real;
	return(num3);
}
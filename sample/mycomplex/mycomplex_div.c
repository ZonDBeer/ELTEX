#include "mycomplex.h"
#include "mycomplex_div.h"
struct _mycomplex _mycomplex_div(struct _mycomplex num1, struct _mycomplex num2) {
	struct _mycomplex num3;
	num3.real = (num1.real*num2.real + num1.imag*num2.imag)
		/ (num2.real*num2.real + num2.imag*num2.imag);
	num3.imag = (num2.real*num1.imag - num1.real*num2.imag)
		/ (num2.real*num2.real + num2.imag*num2.imag);
	return(num3);
}
#include "mycomplex.h"
#include "mycomplex_sub.h"
struct _mycomplex _mycomplex_sub(struct _mycomplex num1, struct _mycomplex num2) {
	num1.real -= num2.real;
	num1.imag -= num2.imag;
	return(num1);
}
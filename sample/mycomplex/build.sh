#!/bin/bash

gcc -w -c mycomplex_add.c mycomplex_sub.c mycomplex_mul.c mycomplex_div.c
ar -rc libmycomplex.a mycomplex_add.o mycomplex_sub.o mycomplex_mul.o mycomplex_div.o
gcc -w -g -O0 main.c -o main -I. -L. -lmycomplex
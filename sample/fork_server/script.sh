#!/bin/bash
for ((i = 0; i < 200000; i++))
do
	./client 127.0.0.1 3434
done
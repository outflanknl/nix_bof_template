#!/bin/sh

ARCH=$(uname -m)
gcc -c -FPIC hello.c -o hello.$ARCH.o

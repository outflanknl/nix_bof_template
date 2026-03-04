#!/bin/sh

ARCH=$(uname -m)
gcc -c -fno-stack-protector -fno-stack-check -Os avenum.c -o avenum.$ARCH.o

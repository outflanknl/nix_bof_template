#!/bin/sh

ARCH=$(uname -m)
gcc -c -FPIC id.c -o id.$ARCH.o

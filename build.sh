#!/bin/sh

for c in *.c; do
    echo ${c%.c};
    gcc $c -o ${c%.c} -lpcap;
done;


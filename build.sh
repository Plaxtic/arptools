#!/bin/sh -e

gcc -r tools/net* -o tools/tools.o;

for c in arp*.c; do
    echo ${c%.c};
    gcc $c tools/tools.o -o ${c%.c} -lpcap;
done;


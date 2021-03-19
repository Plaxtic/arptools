#!/bin/sh -e

# stupid way to protect shell stripts
for sh in *.sh; do
    chmod -x $sh;
done

# delete all executables
find . -maxdepth 1 -type f -executable -delete

# turn .sh back on
for sh in *.sh; do
    chmod +x $sh;
done

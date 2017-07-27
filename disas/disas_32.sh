#!/bin/bash

echo -ne `echo $1 | sed 's/\(..\)/\\\\x\1/g' ` > temp.bin

echo
echo "=== ndisasm ==="
echo
ndisasm -b32 temp.bin

echo
echo "=== objdump ==="
echo
objdump -D -b binary -mi386 temp.bin

echo
echo "=== capstone ==="
echo
python capstone_32.py $1

rm temp.bin


#!/bin/bash

echo -ne `echo $1 | sed 's/\(..\)/\\\\x\1/g' ` > temp.bin

echo
echo "=== ndisasm ==="
echo
ndisasm -b64 temp.bin

echo
echo "=== objdump ==="
echo
objdump -D -b binary -mi386 -Mx86-64 temp.bin

echo
echo "=== capstone ==="
echo
python capstone_64.py $1

rm temp.bin


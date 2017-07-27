from capstone import *
import sys
from binascii import hexlify, unhexlify
import os.path

if os.path.exists(sys.argv[1]):
    with open(sys.argv[1], 'r') as f:
        byte_string = hexlify(f.read())
else:
    byte_string = sys.argv[1]

md = Cs(CS_ARCH_X86, CS_MODE_64)
try:
    (address, size, mnemonic, op_str) = md.disasm_lite(unhexlify(byte_string), 0, 1).next()
except StopIteration:
    mnemonic="(unk)"
    op_str=""
    size = 0

print "%s %s" % (mnemonic, op_str)
print byte_string[:size*2]
print "%d bytes" % size

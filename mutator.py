# instruction mutator

#
# github.com/xoreaxeaxeax/sandsifter // domas // @xoreaxeaxeax
#

# 
# this is a basic example of a mutator to control the x86 injector.  in
# practice, the tunneling mode of the injector performs far better than any
# random or mutating strategy can, but this provides a mutation approach if
# desired.
#

import sys
import subprocess
import random
from struct import *
from capstone import *
from collections import namedtuple
from collections import deque

Result = namedtuple('Result', 'valid length signum sicode')

class insn:
    raw = ""
    processed = False
    pad = ""
    mnemonic = ""
    op_str = ""
    r = Result(False, 0, 0, 0)

q = deque()

SEEDS = 10
MUTATIONS = 10

injector = None

prefixes=[
    "\xf0", # lock
    "\xf2", # repne / bound
    "\xf3", # rep
    "\x2e", # cs / branch taken
    "\x36", # ss / branch not taken
    "\x3e", # ds
    "\x26", # es
    "\x64", # fs
    "\x65", # gs
    "\x66", # data
    "\x67"  # addr
    ]

injector_bitness, errors = subprocess.Popen(['file', 'injector'], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
arch = re.search(r".*(..)-bit.*", injector_bitness).group(1)

if arch == "64":
    # rex prefixes
    prefixes.extend([
        "\x40", "\x41", "\x42", "\x43", "\x44", "\x45", "\x46", "\x47",
        "\x48", "\x49", "\x4a", "\x4b", "\x4c", "\x4d", "\x4e", "\x4f"
        ])

def rand_byte():
    return chr(random.randint(0,255))

# generate an approximate seed instruction
# it is probably fine to just randomize the whole thing
def generate_seed():
    b=""

    # prefix
    if random.randint(0,1)==1:
        b+=random.choice(prefixes)

    # opcode
    o = random.randint(1,3)
    if o==1:
        b+=rand_byte()
    elif o==2:
        b+="\x0f"
        b+=rand_byte()
    elif o==3:
        b+="\x0f\x38"
        b+=rand_byte()

    # modr/m
    b+=rand_byte()

    # sib

    # disp
    b+="".join(rand_byte() for _ in range(4))

    # imm
    b+="".join(rand_byte() for _ in range(4))

    return b

def fix(b):
    if len(b) < INSN_BYTES:
        return b + "".join(rand_byte() for _ in range(INSN_BYTES-len(b)))
    else:
        return b[:INSN_BYTES]

def mutate(b):
    mutation = random.randint(1,5)

    if mutation == 1:
        # insert random byte
        i = random.randint(0,len(b)-1)
        b = b[:i] + rand_byte() + b[i:]
    elif mutation == 2:
        # delete random byte
        i = random.randint(0,len(b)-1)
        b = b[:i] + b[i+1:]
    elif mutation == 3:
        # increment random byte
        i = random.randint(0,len(b)-1)
        b = b[:i] + chr((ord(b[i])+1)%256) + b[i+1:]
    elif mutation == 4:
        # decrement random byte
        i = random.randint(0,len(b)-1)
        b = b[:i] + chr((ord(b[i])-1)%256) + b[i+1:]
    elif mutation == 5:
        # overwrite random byte
        i = random.randint(0,len(b)-1)
        b = b[:i] + rand_byte() + b[i+1:]
    else:
        raise

    if not b:
        b = rand_byte()
    
    return b

def init_mutator():
    random.seed()
    for i in range(1, SEEDS):
        s = insn()
        s.raw = generate_seed()
        q.append(s)

def disas(b):
    try:
        (address, size, mnemonic, op_str) = md.disasm_lite(b, 0x1000, 1).next()
    except StopIteration:
        mnemonic="(unk)"
        op_str=""
    return (mnemonic, op_str)

def run(b):
    injector.stdin.write(b)
    o = injector.stdout.read(INSN_BYTES)
    o = injector.stdout.read(4*RET_INTS)
    return Result(*unpack('iiii', o))

def process(i):
    i.processed = True
    i.pad = fix(i.raw)
    (i.mnemonic, i.op_str) = disas(i.pad)
    sys.stdout.write("%s ... %10s %-45s " % ("".join("{:02x}".format(ord(c)) for c in i.pad[:8]), i.mnemonic, i.op_str))
    sys.stdout.flush()
    i.r = run(i.pad)
    sys.stdout.write("%3d %3d %3d %3d" % (i.r.valid, i.r.length, i.r.signum, i.r.sicode))
    sys.stdout.flush()


INSN_BYTES = 32
RET_INTS = 4

init_mutator()

if arch == "64":
    md = Cs(CS_ARCH_X86, CS_MODE_64)
else:
    md = Cs(CS_ARCH_X86, CS_MODE_32)

injector = subprocess.Popen("./injector -d -R", shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)

while True:
    s = q.popleft()

    if not s.processed:
        process(s)

    found_new = False

    if s.r.valid:
        for i in range(1, MUTATIONS):
            t = insn()
            t.raw = mutate(s.raw)
            process(t)

            if t.r.valid:
                if s.r.length != t.r.length or s.r.signum != t.r.signum or s.r.sicode != t.r.sicode:
                    q.append(t)
                    found_new = True
                    sys.stdout.write(" !")
                else:
                    sys.stdout.write(" x")
            else:
                sys.stdout.write(" x")

            sys.stdout.write(" %6d" % len(q))
            sys.stdout.write("\n")

        if found_new:
            # this was a good seed
            q.append(s)

try:
    injector.kill()
except OSError:
    pass


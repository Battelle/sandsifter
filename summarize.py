#!/usr/bin/python

# we had a much more automated and intelligent approach to reducing the log, but
# could not come up with a reasonable way to differentiate between a modr/m byte
# and an opcode byte.  e.g. if the instruction is xxyy..., and changing xx or yy
# changes the instruction length, is yy an opcode byte or a modr/m byte?
# without being able to make this determination, we cannot succinctly summarize
# the instructions.  rewrote the summarizer as a more manual tool, which seems
# to give pretty good results without requiring a lot of work or knowledge.

#TODO: capstone's performance is still terrible.  maybe i do need a
# preprocessing step to disassemble everything?  i'm afraid that could take
# forever with how slow capstone is

import subprocess
from capstone import *
from pyutil.progress import progress
from collections import namedtuple
from binascii import *
import sys
import time
import tempfile
import os
import locale

from gui.gui import *

# TODO: some of our disassemblers don't allow us to specify a number of
# instructions to disassemble.  this can create an issue where, if the
# disassembler believes one instruction is actually two instructions, we have no
# way to know that the disassembler has made a mistake (without relying on
# existing knowledge about the instruction set).  for now, this is just a known
# limitation.

CAPSTONE = "capstone"

# i wanted to bring in capstone this way so that it would match the
# necessary format of the other disassemblers.  however, the performance
# is fairly unusable like this.  we'll integrate capstone directly instead 
'''
    "capstone":
        {
            "check_supported": False,
            32: (
                    # disassemble
                    "python disas/capstone_32.py"
                    " {0}"              # disassemble
                    "| head -1"         # grab disassembly
                    ,
                    # raw
                    "python disas/capstone_32.py"
                    " {0}"              # disassemble
                    "| head -2"         # grab raw
                    "| tail -1"
                ),
            64: (
                    # disassemble
                    "python disas/capstone_64.py"
                    " {0}"              # disassemble
                    "| head -1"         # grab disassembly
                    ,
                    # raw
                    "python disas/capstone_64.py"
                    " {0}"              # disassemble
                    "| head -2"         # grab raw
                    "| tail -1"
                ),
        },
'''

# many disassemblers break all or unexpected prefixes onto separate lines, 
# we need to combine these into one instruction for meaningful results
disassemblers = {
    CAPSTONE: { "check_supported": False, 32: None, 64: None },
    "ndisasm":
        {
            "check_supported": True,
            32: (
                    # disassemble
                    "ndisasm"
                    " -b32 {0}"         # disassemble
                    "| tr A-Z a-z"      # lowercase
                    "| sed '/ db /Q'"   # stop at invalid byte
                    "| sed 's/[0-9a-f]* *[0-9a-f]* *//'" # crop instructions
                    "| awk 'ORS=\" \"'" # join to one line
                    ,
                    # raw
                    "ndisasm"
                    " -b32 {0}"         # disassemble
                    "| tr A-Z a-z"      # lowercase
                    "| sed '/ db /Q'"   # stop at invalid byte
                    "| sed 's/[0-9a-f]* *\\([0-9a-f]*\\) *.*/\\1/'" # crop raw
                    "| tr -d '\\n'"     # join to one line
                ),
            64: (
                    # disassemble
                    "ndisasm"
                    " -b64 {0}"         # disassemble
                    "| tr A-Z a-z"      # lowercase
                    "| sed '/ db /Q'"   # stop at invalid byte
                    "| sed 's/[0-9a-f]* *[0-9a-f]* *//'" # crop instructions
                    "| awk 'ORS=\" \"'" # join to one line
                    ,
                    # raw
                    "ndisasm"
                    " -b64 {0}"         # disassemble
                    "| tr A-Z a-z"      # lowercase
                    "| sed '/ db /Q'"   # stop at invalid byte
                    "| sed 's/[0-9a-f]* *\\([0-9a-f]*\\) *.*/\\1/'" # crop raw
                    "| tr -d '\\n'"     # join to one line
                ),
        },
    "objdump": 
        {
            "check_supported": True,
            32: (
                    # disassemble
                    "objdump"
                    " -D -b binary -mi386 -Mintel --no-show-raw-insn {0}"
                    "| tr A-Z a-z"           # lowercase
                    "| grep '0:' -A 99"      # crop header
                    "| sed '/.byte /Q'"      # stop at invalid byte
                    "| sed '/(bad)/Q'"       # stop at invalid byte
                    "| sed 's/.*:\\s*//'"    # crop instructions
                    "| awk 'ORS=\" \"'"      # join to one line
                    ,
                    # raw
                    "objdump"
                    " -D -b binary -mi386 -Mintel --insn-width=16 {0}"
                    "| tr A-Z a-z"           # lowercase
                    "| grep '0:' -A 99"      # crop header
                    "| sed '/.byte /Q'"      # stop at invalid byte
                    "| sed '/(bad)/Q'"       # stop at invalid byte
                    "| sed 's/.*:\s*\(\([0-9a-f][0-9a-f] \)*\).*/\1/'" # crop raw
                    "| tr -d '\\n '"         # join to one line and remove spaces
                ),
            64: (
                    # disassemble
                    "objdump"
                    " -D -b binary -mi386 -Mx86-64 -Mintel --no-show-raw-insn {0}"
                    "| tr A-Z a-z"           # lowercase
                    "| grep '0:' -A 99"      # crop header
                    "| sed '/.byte /Q'"      # stop at invalid byte
                    "| sed '/(bad)/Q'"       # stop at invalid byte
                    "| sed 's/.*:\\s*//'"    # crop instructions
                    "| awk 'ORS=\" \"'"      # join to one line
                    ,
                    # raw
                    "objdump"
                    " -D -b binary -mi386 -Mx86-64 -Mintel --insn-width=16 {0}"
                    "| tr A-Z a-z"           # lowercase
                    "| grep '0:' -A 99"      # crop header
                    "| sed '/.byte /Q'"      # stop at invalid byte
                    "| sed '/(bad)/Q'"       # stop at invalid byte
                    "| sed 's/.*:\\s*\\(\\([0-9a-f][0-9a-f] \\)*\\).*/\\1/'" # crop raw
                    "| tr -d '\\n '"         # join to one line and remove spaces
                ),
        }
    }
supported = {}

prefixes_32 = [
		0xf0, # lock
		0xf2, # repne / bound
		0xf3, # rep
		0x2e, # cs / branch taken
		0x36, # ss / branch not taken
		0x3e, # ds
		0x26, # es
		0x64, # fs
		0x65, # gs
		0x66, # data
		0x67, # addr
            ]
prefixes_64 = [
                0x40, # rex
                0x41,
                0x42,
                0x43,
                0x44,
                0x45,
                0x46,
                0x47,
                0x48,
                0x49,
                0x4a,
                0x4b,
                0x4c,
                0x4d,
                0x4e,
                0x4f,
            ]

# capstone
md_32 = Cs(CS_ARCH_X86, CS_MODE_32)
md_64 = Cs(CS_ARCH_X86, CS_MODE_64)

def disassemble_capstone(arch, data):
    if arch == 32:
        m = md_32
    elif arch == 64:
        m = md_64
    else:
        return ("", "")

    try:
        (address, size, mnemonic, op_str) = m.disasm_lite(data, 0, 1).next()
    except StopIteration:
        mnemonic="(unk)"
        op_str=""
        size = 0

    return ("%s %s" % (mnemonic, op_str), hexlify(data[:size]))

signals = {
        1:   "sighup",
        2:   "sigint",
        3:   "sigquit",
        4:   "sigill",
        5:   "sigtrap",
        6:   "sigiot",
        7:   "sigbus",
        8:   "sigfpe",
        9:   "sigkill",
        10:  "sigusr1",
        11:  "sigsegv",
        12:  "sigusr2",
        13:  "sigpipe",
        14:  "sigalrm",
        15:  "sigterm",
        16:  "sigstkflt",
        17:  "sigchld",
        18:  "sigcont",
        19:  "sigstop",
        20:  "sigtstp",
        21:  "sigttin",
        22:  "sigttou",
        23:  "sigurg",
        24:  "sigxcpu",
        25:  "sigxfsz",
        26:  "sigvtalrm",
        27:  "sigprof",
        28:  "sigwinch",
        29:  "sigio",
        30:  "sigpwr",
        }

Result = namedtuple('Result', 'raw long_raw valid length signum sicode')
#TODO: is this hashing well?
CondensedResult = namedtuple('CondensedResult', 'raw valids lengths signums sicodes prefixes')

'''
class CondensedResult(object):
    raw = None
    valids = None
    lengths = None
    signums = None
    sicodes = None
    prefixes = None

    def __init__(self, raw, valids, lengths, signums, sicodes, prefixes):
        self.raw = raw
        self.valids = valids
        self.lengths = lengths
        self.signums = signums
        self.sicodes = sicodes
        self.prefixes = prefixes
'''

class Processor(object):
    processor = "n/a"
    vendor_id = "n/a"
    cpu_family = "n/a"
    model = "n/a"
    model_name = "n/a"
    stepping = "n/a"
    microcode = "n/a"
    architecture = 32

class Catalog(object):
    def __init__(self, d, v, base='', count=0, collapsed=True, example='',
            valids=(), lengths=(), signums=(), sicodes=(), prefixes=()):
        self.d = d # dict
        self.v = v # values
        self.base = base
        self.count = count
        self.collapsed = collapsed
        self.example = example
        self.valids = valids
        self.lengths = lengths
        self.signums = signums
        self.sicodes = sicodes
        self.prefixes = prefixes

def check_disassembler(name):
    result, errors = \
        subprocess.Popen(
                ['which', name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
                ).communicate()
    return result.strip() != ""

def disassemble(disassembler, bitness, data):
    if supported[disassembler] and disassemblers[disassembler][bitness]:
        temp_file = tempfile.NamedTemporaryFile()
        temp_file.write(data)

        # disassemble
        result, errors = \
            subprocess.Popen(
                    disassemblers[disassembler][bitness][0].format(temp_file.name),
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                    ).communicate()

        disas = cleanup(result)

        # raw
        result, errors = \
            subprocess.Popen(
                    disassemblers[disassembler][bitness][1].format(temp_file.name),
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                    ).communicate()

        raw = cleanup(result)

        temp_file.close()

        return (disas, raw)
    else:
        return (None, None)

def cleanup(disas):
    disas = disas.strip()
    disas = disas.replace(',', ', ')
    disas = " ".join(disas.split())
    return disas

def instruction_length(raw):
    return len(raw)/2

def print_catalog(c, depth=0):
    for v in c.v:
        print "  " * (depth) + hexlify(v.raw) + " " + summarize_prefixes(v)
    for k in c.d:
        print "  " * depth + "%02x" % ord(k) + ":"
        print_catalog(c.d[k], depth+1)

def strip_prefixes(i, prefixes):
    while i and ord(i[0]) in prefixes:
        i = i[1:]
    return i

def get_prefixes(i, prefixes):
    p = set()
    for b in i:
        if ord(b) in prefixes:
            p.add(ord(b))
        else:
            break
    return p

def summarize(s, f="%02x"):
    if not s:
        return ""
    s = sorted(list(s))
    l = []
    start = s[0]
    end = start
    for (i, e) in enumerate(s):
        if i + 1 < len(s):
            if end + 1 == s[i + 1]:
                end = s[i + 1]
                continue
        if start == end:
            l.append(f % start)
        else:
            l.append(f % start + "-" + f % end)
        if i + 1 < len(s):
            start = s[i + 1]
            end = start
    return ",".join(l)

def summarize_prefixes(i):
    if 0 in i.prefixes:
        prefixes = summarize(i.prefixes - {0})
        if prefixes:
            prefixes = "(__," + prefixes + ")"
        else:
            prefixes = "(__)"
    else:
        prefixes = "(" + summarize(i.prefixes) + ")"
    return prefixes

def summarize_valids(i):
    return "(" + summarize(i.valids, f="%d") + ")"

def summarize_lengths(i):
    return "(" + summarize(i.lengths, f="%d") + ")"

def summarize_signums(i):
    return "(" + summarize(i.signums, f="%d") + ")"

def summarize_signames(i):
    return "(" + ",".join([signals[s] for s in i.signums]) + ")"

def summarize_sicodes(i):
    return "(" + summarize(i.sicodes, f="%d") + ")"

def merge_sets(instructions, attribute):
    s = set()
    for i in instructions:
        s = s | getattr(i, attribute)
    return s

if __name__ == "__main__":

    #TODO: you need to track the WHOLE byte string and pass that to the
    # disassemblers - if the string was SHORTER than the disassembler thought,
    # i'm not passing the disas enough infomration to recover what it was
    # thinking

    # verify disassemblers are installed
    for disassembler in disassemblers:
        if disassemblers[disassembler]["check_supported"]:
            supported[disassembler] = check_disassembler(disassembler)
        else:
            supported[disassembler] = True

    instructions = []
    processor = Processor()

    print
    print "beginning summarization."
    print "note: this process may take up to an hour to complete, please be patient."
    print

    print "loading sifter log:"
    with open(sys.argv[1], "r") as f:
        lines = f.readlines()
        f.seek(0)
        for (i, l) in enumerate(lines):
            progress(i, len(lines)-1, refresh=len(lines)/1000)
            if l.startswith("#"):
                #TODO: this is not robust
                if "arch:" in l and "64" in l:
                    processor.architecture = 64
                elif "processor\t:" in l:
                    processor.processor = l.split(":",1)[1].strip()
                elif "vendor_id\t:" in l:
                    processor.vendor_id = l.split(":",1)[1].strip()
                elif "cpu family\t:" in l:
                    processor.cpu_family = l.split(":",1)[1].strip()
                elif "model\t:" in l:
                    processor.cpu_family = l.split(":",1)[1].strip()
                elif "model name\t:" in l:
                    processor.model_name = l.split(":",1)[1].strip()
                elif "stepping\t:" in l:
                    processor.stepping = l.split(":",1)[1].strip()
                elif "stepping\t:" in l:
                    processor.microcode = l.split(":",1)[1].strip()
                continue
            v = l.split()
            r = Result(unhexlify(v[0]), unhexlify(v[5].strip("()")), int(v[1]), int(v[2]), int(v[3]), int(v[4]))
            instructions.append(r)

    # reduce prefixes

    prefixes = prefixes_32
    if processor.architecture == 64:
        prefixes.extend(prefixes_64)

    # condense prefixed instructions 
    print "condensing prefixes:"
    all_results = {} # lookup table for condensed result to all results
    d = {} # lookup table for base instruction to instruction summary
    for (c, i) in enumerate(instructions):
        progress(c, len(instructions) - 1, refresh=len(instructions)/1000)
        s = strip_prefixes(i.raw, prefixes)
        p = get_prefixes(i.raw, prefixes)
        if len(s) == len(i.raw):
            p.add(0)
        if s in d:
            d[s].valids.add(i.valid)
            #d[s].lengths.add(i.length)
            d[s].lengths.add(len(s)) # use the stripped length
            d[s].signums.add(i.signum)
            d[s].sicodes.add(i.sicode)
            [d[s].prefixes.add(x) for x in p]
            #TODO: is this taking a long time?
            #all_results[d[s]].append(i)
        else:
            d[s] = CondensedResult(
                    s,
                    set([i.valid]),
                    #set([i.length]),
                    set([len(s)]),
                    set([i.signum]),
                    set([i.sicode]),
                    p
                    )
            #all_results[d[s]] = [i]
    instructions = list(d.values())

    def bin(instructions, index, base="", bin_progress=0, progress_out_of=None):
        valids = merge_sets(instructions, 'valids')
        lengths = merge_sets(instructions, 'lengths')
        signums = merge_sets(instructions, 'signums')
        sicodes = merge_sets(instructions, 'sicodes')
        prefixes = merge_sets(instructions, 'prefixes')

        c = Catalog({}, [], base=base, count=len(instructions), collapsed=True,
                example=instructions[0].raw, valids=valids, lengths=lengths,
                signums=signums, sicodes=sicodes, prefixes=prefixes)

        if not progress_out_of:
            progress_out_of = len(instructions)
        for i in instructions:
            if len(i.raw) > index:
                b = i.raw[index]
                if b in c.d:
                    c.d[b].append(i)
                else:
                    c.d[b] = [i]
            else:
                c.v.append(i)
                bin_progress = bin_progress + 1
                progress(bin_progress, progress_out_of, refresh=progress_out_of/1000)
        for b in c.d:
            (c.d[b], bin_progress) = bin(c.d[b], index + 1, base + b, bin_progress, progress_out_of)
        return (c, bin_progress)

    print "binning results:"
    (c,_) = bin(instructions, 0)

    # open first catalog entries
    c.collapsed = False

    # open known 2 byte opcode entries
    if '\x0f' in c.d:
        c.d['\x0f'].collapsed = False

    #TODO:
    # should i break this up into a summarize and browse script
    # that way i could pickle the summary results so i don't have to do that
    # every time

    #TODO:
    # in summary, something like "hardware bug" "software bug" "hidden instruction"
    # then in each of the catalog details, summarize that too: "(3) hardware
    # bugs, (20) hidden instructions, (0) software bugs"
    # the only downside is that requires disassembling everything from the
    # start... which could take a long time for any of the non-capstone ones

    #TODO: ideally we would have a map of the opcodes on each vendor, so we
    # could conclusively say "this is undocumented" for the target vendor, instead
    # of relying on the disassembler.  but this gets thorny in a hurry

    def get_solo_leaf(c):
        assert c.count == 1
        if c.v:
            return c.v[0]
        else:
            return get_solo_leaf(c.d[c.d.keys()[0]])

    def build_instruction_summary(c, index=0, summary=None, lookup=None):
        if not summary:
            summary = []
        if not lookup:
            lookup = {}
        if c.count > 1:
            lookup[len(summary)] = c
            suffix = ".." * (min(c.lengths) - len(c.base)) + " " + \
                            ".." * (max(c.lengths) - min(c.lengths))
            summary.append("  " * index + "> " + hexlify(c.base) + suffix)
            if not c.collapsed:
                for b in sorted(c.d):
                    build_instruction_summary(c.d[b], index + 1, summary, lookup)
                for v in sorted(c.v):
                    lookup[len(summary)] = v
                    summary.append("  " * index + "  " + hexlify(v.raw))
        else:
            v = get_solo_leaf(c)
            lookup[len(summary)] = v
            summary.append("  " * index + "  " + hexlify(v.raw))
        return (summary, lookup)

    (summary, lookup) = build_instruction_summary(c)

    #TODO scroll window height based on screen height
    gui = Gui(no_delay = False)

    textbox = TextBox(gui, gui.window, 1, 3, 35, 30, gui.gray(.1), 
            summary, gui.gray(.6), curses.color_pair(gui.RED))

    def draw_infobox(gui, o):
        infobox_x = 37
        infobox_y = 3
        infobox_width = 60
        infobox_height = 30
        gui.box(gui.window, infobox_x, infobox_y, infobox_width, infobox_height, gui.gray(.3))

	#TODO: (minor) this should really be done properly with windows
        for i in xrange(infobox_y + 1, infobox_y + infobox_height - 1):
            gui.window.addstr(i, infobox_x + 1, " " * (infobox_width - 2), gui.gray(0))

        if type(o) == Catalog:
            line = infobox_y + 1

            gui.window.addstr(line, infobox_x + 2, "instruction group:", curses.color_pair(gui.RED))
            line = line + 1

            g = hexlify(o.base)
            if not g:
                g = "(all)"
            gui.window.addstr(line, infobox_x + 2, "%s" % g, gui.gray(1))
            line = line + 1

            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "instructions found in this group:", gui.gray(.5))
            line = line + 1
            gui.window.addstr(line, infobox_x + 2, "%d" % o.count, gui.gray(.8))
            line = line + 1

            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "example instruction from this group:", gui.gray(.5))
            line = line + 1
            gui.window.addstr(line, infobox_x + 2, "%s" % hexlify(o.example), gui.gray(.8))
            line = line + 1

            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "group attribute summary:", gui.gray(.8))
            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "valid:", gui.gray(.5))
            gui.window.addstr(line, infobox_x + 18, "%-30s" % summarize_valids(o), gui.gray(.8))
            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "length:", gui.gray(.5))
            gui.window.addstr(line, infobox_x + 18, "%-30s" % summarize_lengths(o), gui.gray(.8))
            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "signum:", gui.gray(.5))
            gui.window.addstr(line, infobox_x + 18, "%-30s" % summarize_signums(o), gui.gray(.8))
            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "signal:", gui.gray(.5))
            gui.window.addstr(line, infobox_x + 18, "%-30s" % summarize_signames(o), gui.gray(.8))
            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "sicode:", gui.gray(.5))
            gui.window.addstr(line, infobox_x + 18, "%-30s" % summarize_sicodes(o), gui.gray(.8))
            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "prefixes:", gui.gray(.5))
            gui.window.addstr(line, infobox_x + 18, "%-30s" % summarize_prefixes(o), gui.gray(.8))
            line = line + 1

        elif type(o) == CondensedResult:
            line = infobox_y + 1

            gui.window.addstr(line, infobox_x + 2, "instruction:", curses.color_pair(gui.RED))
            line = line + 1
            gui.window.addstr(line, infobox_x + 2, "%-30s" % hexlify(o.raw), gui.gray(1))
            line = line + 1

            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "prefixes:", gui.gray(.5))
            gui.window.addstr(line, infobox_x + 18, "%-30s" % summarize_prefixes(o), gui.gray(.8))
            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "valids:", gui.gray(.5))
            gui.window.addstr(line, infobox_x + 18, "%-30s" % summarize_valids(o), gui.gray(.8))
            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "lengths:", gui.gray(.5))
            gui.window.addstr(line, infobox_x + 18, "%-30s" % summarize_lengths(o), gui.gray(.8))
            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "signums:", gui.gray(.5))
            gui.window.addstr(line, infobox_x + 18, "%-30s" % summarize_signums(o), gui.gray(.8))
            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "signals:", gui.gray(.5))
            gui.window.addstr(line, infobox_x + 18, "%-30s" % summarize_signames(o), gui.gray(.8))
            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "sicodes:", gui.gray(.5))
            gui.window.addstr(line, infobox_x + 18, "%-30s" % summarize_sicodes(o), gui.gray(.8))
            line = line + 1

            line = line + 1

            gui.window.addstr(line, infobox_x + 2, "analysis:", curses.color_pair(gui.RED))
            line = line + 1

            for disassembler in sorted(disassemblers):
                #TODO: (minor) is there a better way to do this, that doesn't
                # involve assuming a prefix
                if 0 in o.prefixes:
                    # a no prefix version observed, use that
                    dis_data = o.raw
                else:
                    # select a prefixed version as an exemplar instruction
                    dis_data = chr(next(iter(o.prefixes))) + o.raw

                if disassembler == CAPSTONE:
                    (asm, raw) = disassemble_capstone(processor.architecture, dis_data)
                else:
                    (asm, raw) = disassemble(disassembler, processor.architecture, dis_data)
                if not asm:
                    asm = "(unknown)"
                if not raw:
                    raw = "n/a"

                gui.window.addstr(line, infobox_x + 2, "%s:" % disassembler, gui.gray(.5))
                line = line + 1

                gui.window.addstr(line, infobox_x + 4, "%-30s" % asm, gui.gray(.8))
                line = line + 1
                gui.window.addstr(line, infobox_x + 4, "%-30s" % raw, gui.gray(.5))
                line = line + 1

                line = line + 1
    
    while True:

        detail_string = \
            "arch: %d / processor: %s / vendor: %s / family: %s / " \
            "model: %s / stepping: %s / ucode: %s" % \
            (
                processor.architecture,
                processor.processor,
                processor.vendor_id,
                processor.cpu_family,
                processor.model,
                processor.stepping,
                processor.microcode,
            )
        gui.window.addstr(1, 1, processor.model_name, gui.gray(1))
        gui.window.addstr(2, 1, detail_string, gui.gray(.6))

        textbox.draw()

        draw_infobox(gui, lookup[textbox.selected_index])

        gui.window.addstr(33, 1, "j: down,     J: DOWN", gui.gray(.4))
        gui.window.addstr(34, 1, "k: up,       K: UP", gui.gray(.4))
        gui.window.addstr(35, 1, "l: expand    L: all", gui.gray(.4))
        gui.window.addstr(36, 1, "h: collapse  H: all", gui.gray(.4))
        gui.window.addstr(37, 1, "g: start     G: end", gui.gray(.4))
        gui.window.addstr(38, 1, "{: previous  }: next", gui.gray(.4))
        gui.window.addstr(39, 1, "q: quit and print", gui.gray(.4))

        gui.refresh()

        def smooth_scroll():
            # unnecessary smoother scroll effect
            textbox.draw()
            draw_infobox(gui, lookup[textbox.selected_index])
            gui.refresh()
            time.sleep(.01)

        key = -1
        while key == -1:
            key = gui.get_key()
        if key == ord('k'):
            textbox.scroll_up()
        elif key == ord('K'):
            for _ in xrange(10):
                textbox.scroll_up()
                smooth_scroll()
        elif key == ord('j'):
            textbox.scroll_down()
        elif key == ord('J'):
            for _ in xrange(10):
                textbox.scroll_down()
                smooth_scroll()
        elif key == ord('l'):
            i = textbox.selected_index
            v = lookup[i]
            if type(v) == Catalog:
                lookup[i].collapsed = False
                (summary, lookup) = build_instruction_summary(c)
                textbox.text = summary
        elif key == ord('L'):
            def expand_all(c):
                c.collapsed = False
                for b in c.d:
                    expand_all(c.d[b])
            expand_all(c)
            (summary, lookup) = build_instruction_summary(c)
            textbox.text = summary
        elif key == ord('h'):
            i = textbox.selected_index
            v = lookup[i]
            if type(v) == Catalog:
                lookup[i].collapsed = True
                (summary, lookup) = build_instruction_summary(c)
                textbox.text = summary
        elif key == ord('H'):
            def collapse_all(c):
                c.collapsed = True
                for b in c.d:
                    collapse_all(c.d[b])
            collapse_all(c)
            (summary, lookup) = build_instruction_summary(c)
            textbox.text = summary
        elif key == ord('g'):
            textbox.scroll_top()
        elif key == ord('G'):
            textbox.scroll_bottom()
        elif key == ord('{'):
            textbox.scroll_up()
            while not textbox.at_top() and \
                    type(lookup[textbox.selected_index]) != Catalog:
                textbox.scroll_up()
                smooth_scroll()
        elif key == ord('}'):
            textbox.scroll_down()
            while not textbox.at_bottom() and \
                    type(lookup[textbox.selected_index]) != Catalog:
                textbox.scroll_down()
                smooth_scroll()
        elif key == ord('q'):
            break

    gui.stop()

    os.system('clear')

    title = "PROCESSOR ANALYSIS SUMMARY"
    width = 50
    print "=" * width
    print " " * ((width - len(title)) / 2) + title
    print "=" * width
    print
    print processor.model_name
    print
    print " arch:       %d" % processor.architecture
    print " processor:  %s" % processor.processor
    print " vendor_id:  %s" % processor.vendor_id
    print " cpu_family: %s" % processor.cpu_family
    print " model:      %s" % processor.model
    print " stepping:   %s" % processor.stepping
    print " microcode:  %s" % processor.microcode
    print 

    #TODO:
    # high level summary at end:
    #   undocumented instructions found: x
    #   software bugs detected: x
    #   hardware bugs detected: x
    for x in summary:
        print x


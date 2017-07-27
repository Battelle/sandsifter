#!/usr/bin/python

# instruction injector frontend

#
# github.com/xoreaxeaxeax/sandsifter // domas // @xoreaxeaxeax
#

# run as sudo for best results

import signal
import sys
import subprocess
import os
from struct import *
from capstone import *
from collections import namedtuple
from collections import deque
import threading
import time
import curses
from binascii import hexlify
import re
import random
import argparse
import code
import copy
from ctypes import *

INJECTOR = "./injector"
arch = ""

OUTPUT = "./data/"
LOG  = OUTPUT + "log"
SYNC = OUTPUT + "sync"
TICK = OUTPUT + "tick"
LAST = OUTPUT + "last"

class ThreadState:
    pause = False
    run = True

class InjectorResults(Structure):
    _fields_ = [('disas_length', c_int),
                ('disas_known', c_int),
                ('raw_insn', c_ubyte * 16),
                ('valid', c_int),
                ('length', c_int),
                ('signum', c_int),
                ('sicode', c_int),
                ('siaddr', c_int),
		]

class Settings:
    SYNTH_MODE_RANDOM = "r"
    SYNTH_MODE_BRUTE = "b"
    SYNTH_MODE_TUNNEL = "t"
    synth_mode = SYNTH_MODE_RANDOM
    root = False
    seed = 0
    args = ""

    def __init__(self, args):
        if "-r" in args:
            self.synth_mode = self.SYNTH_MODE_RANDOM
        elif "-b" in args:
            self.synth_mode = self.SYNTH_MODE_BRUTE
        elif "-t" in args:
            self.synth_mode = self.SYNTH_MODE_TUNNEL
        self.args = args
        self.root = (os.geteuid() == 0)
        self.seed = random.getrandbits(32)

    def increment_synth_mode(self):
        if self.synth_mode == self.SYNTH_MODE_BRUTE:
            self.synth_mode = self.SYNTH_MODE_RANDOM
        elif self.synth_mode == self.SYNTH_MODE_RANDOM:
            self.synth_mode = self.SYNTH_MODE_TUNNEL
        elif self.synth_mode == self.SYNTH_MODE_TUNNEL:
            self.synth_mode = self.SYNTH_MODE_BRUTE

class Tests:
    r = InjectorResults() # current result
    IL=20 # instruction log len
    UL=10 # artifact log len
    il = deque(maxlen=IL) # instruction log
    al = deque(maxlen=UL) # artifact log
    ad = dict() # artifact dict
    ic = 0 # instruction count
    ac = 0 # artifact count
    start_time = time.time()

    def elapsed(self):
        m, s = divmod(time.time() - self.start_time, 60)
        h, m = divmod(m, 60)
        return "%02d:%02d:%02d.%02d" % (h, m, int(s), int(100*(s-int(s))) )

class Tee(object):
    def __init__(self, name, mode):
        self.file = open(name, mode)
        self.stdout = sys.stdout
        sys.stdout = self
    def __del__(self):
        sys.stdout = self.stdout
        self.file.close()
    def write(self, data):
        self.file.write(data)
        self.stdout.write(data)

# capstone disassembler
md = None
def disas_capstone(b):
    global md, arch
    if not md:
        if arch == "64":
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
    try:
        (address, size, mnemonic, op_str) = md.disasm_lite(b, 0, 1).next()
    except StopIteration:
        mnemonic="(unk)"
        op_str=""
        size = 0
    return (mnemonic, op_str, size)

# ndisasm disassembler
# (ndidsasm breaks unnecessary prefixes onto its own line, which makes parsing
# the output difficult.  really only useful with the -P0 flag to disallow
# prefixes)
def disas_ndisasm(b):
    b = ''.join('\\x%02x' % ord(c) for c in b)
    if arch == "64":
        dis, errors = subprocess.Popen("echo -ne '%s' | ndisasm -b64 - | head -2" % b,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()
    else:
        dis, errors = subprocess.Popen("echo -ne '%s' | ndisasm -b32 - | head -2" % b,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()
    dis = dis.split("\n")
    extra = dis[1]
    dis = dis[0].split(None, 4)
    if extra.strip()[0] == '-':
        dis[1] = dis[1] + extra.strip()[1:]

    address = dis[0]
    insn = dis[1]
    mnemonic = dis[2]
    if len(dis) > 3:
        op_str = dis[3]
    else:
        op_str = ""

    if mnemonic == "db":
        mnemonic = "(unk)"
        insn = ""
        op_str = ""
    size = len(insn)/2

    return (mnemonic, op_str, size)

# objdump disassembler
# (objdump breaks unnecessary prefixes onto its own line, which makes parsing
# the output difficult.  really only useful with the -P0 flag to disallow
# prefixes)
def disas_objdump(b):
    with open("/dev/shm/shifter", "w") as f:
        f.write(b)
    if arch == "64":
        dis, errors = subprocess.Popen("objdump -D --insn-width=256 -b binary \
                -mi386 -Mx86-64 /dev/shm/shifter | head -8 | tail -1",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()
    else:
        dis, errors = subprocess.Popen("objdump -D --insn-width=256 -b binary \
                -mi386 /dev/shm/shifter | head -8 | tail -1",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()
    dis = dis[6:] # address
    raw = dis[:256*3].replace(" ","")
    dis = dis[256*3:].strip().split(None, 2)
    mnemonic = dis[0]
    if len(dis) > 1:
        op_str = dis[1]
    else:
        op_str = ""
    if mnemonic == "(bad)":
        mnemonic = "(unk)"
        insn = ""
        op_str = ""
    size = len(raw)/2
    return (mnemonic, op_str, size)

def cstr2py(s):
    return ''.join([chr(x) for x in s])

# targeting python 2.6 support
def int_to_comma(x):
    if type(x) not in [type(0), type(0L)]:
        raise TypeError("Parameter must be an integer.")
    if x < 0:
        return '-' + int_to_comma(-x)
    result = ''
    while x >= 1000:
        x, r = divmod(x, 1000)
        result = ",%03d%s" % (r, result)
    return "%d%s" % (x, result)

def result_string(insn, result):
    s = "%30s %2d %2d %2d %2d (%s)\n" % (
            hexlify(insn), result.valid,
            result.length, result.signum,
            result.sicode, hexlify(cstr2py(result.raw_insn)))
    return s

class Injector:
    process = None
    settings = None
    command = None

    def __init__(self, settings):
        self.settings = settings

    def start(self):
        self.command = "%s %s -%c -R %s -s %d" % \
                (
                    INJECTOR,
                    " ".join(self.settings.args),
                    self.settings.synth_mode,
                    "-0" if self.settings.root else "",
                    self.settings.seed
                )
        self.process = subprocess.Popen(
            "exec %s" % self.command,
            shell=True,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            preexec_fn=os.setsid
            )
        
    def stop(self):
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except OSError:
                pass

class Poll:
    SIGILL = 4
    SIGSEGV = 11
    SIGFPE = 8
    SIGBUS = 7
    SIGTRAP = 5

    def __init__(self, ts, injector, tests, command_line, sync=False, low_mem=False, search_unk=True,
            search_len=False, search_dis=False, search_ill=False, disassembler=disas_capstone):
        self.ts = ts
        self.injector = injector
        self.T = tests
        self.poll_thread = None
        self.sync = sync
        self.low_mem = low_mem
        self.search_len = search_len
        self.search_unk = search_unk
        self.search_dis = search_dis
        self.search_ill = search_ill
        self.disas = disassembler

        if self.sync:
            with open(SYNC, "w") as f:
                f.write("#\n")
                f.write("# %s\n" % command_line)
                f.write("# %s\n" % injector.command)
                f.write("#\n")
                f.write("# cpu:\n")
                cpu = get_cpu_info()
                for l in cpu:
                    f.write("# %s\n" % l)
                f.write("# %s  v  l  s  c\n" % (" " * 28))

    def start(self):
        self.poll_thread = threading.Thread(target=self.poll)
        self.poll_thread.start()

    def stop(self):
        self.poll_thread.join()
        while self.ts.run:
            time.sleep(.1)

    def poll(self):
        while self.ts.run:
            while self.ts.pause:
                time.sleep(.1)

            bytes_polled = self.injector.process.stdout.readinto(self.T.r)

            if bytes_polled == sizeof(self.T.r):
                self.T.ic = self.T.ic + 1

                error = False
                if self.T.r.valid:
                    if self.search_unk and not self.T.r.disas_known and self.T.r.signum != self.SIGILL:
                        error = True
                    if self.search_len and self.T.r.disas_known and self.T.r.disas_length != self.T.r.length:
                        error = True
                    if self.search_dis and self.T.r.disas_known \
                        and self.T.r.disas_length != self.T.r.length and self.T.r.signum != self.SIGILL:
                        error = True
                    if self.search_ill and self.T.r.disas_known and self.T.r.signum == self.SIGILL:
                        error = True
                if error:
                    insn = cstr2py(self.T.r.raw_insn)[:self.T.r.length]
                    r = copy.deepcopy(self.T.r)
                    self.T.al.appendleft(r)
                    if insn not in self.T.ad:
                        if not self.low_mem:
                            self.T.ad[insn] = r
                        self.T.ac = self.T.ac + 1
                        if self.sync:
                            with open(SYNC, "a") as f:
                                f.write(result_string(insn, self.T.r))
            else:
                if self.injector.process.poll() is not None:
                    self.ts.run = False
                    break

class Gui:
    TIME_SLICE = .01
    GRAY_BASE = 50
    TICK_MASK = 0xff
    RATE_Q = 100
    RATE_FACTOR = 1000

    INDENT = 10

    GRAYS = 50

    BLACK = 1
    WHITE = 2
    BLUE =  3
    RED =   4
    GREEN = 5

    COLOR_BLACK = 16
    COLOR_WHITE = 17
    COLOR_BLUE =  18
    COLOR_RED =   19
    COLOR_GREEN = 20

    def __init__(self, ts, injector, tests, do_tick, disassembler=disas_capstone):
        self.ts = ts;
        self.injector = injector
        self.T = tests
        self.gui_thread = None
        self.do_tick = do_tick
        self.ticks = 0

        self.last_ins_count = 0
        self.delta_log = deque(maxlen=self.RATE_Q)
        self.time_log = deque(maxlen=self.RATE_Q)

        self.disas = disassembler

        self.stdscr = curses.initscr()
        curses.start_color()

        # doesn't work
        # self.orig_colors = [curses.color_content(x) for x in xrange(256)]

        curses.use_default_colors()
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)
        self.stdscr.nodelay(1)

        self.sx = 0
        self.sy = 0

        self.init_colors()

        self.stdscr.bkgd(curses.color_pair(self.WHITE))

        self.last_time = time.time()

    def init_colors(self):
        if curses.has_colors() and curses.can_change_color():
            curses.init_color(self.COLOR_BLACK, 0, 0, 0)
            curses.init_color(self.COLOR_WHITE, 1000, 1000, 1000)
            curses.init_color(self.COLOR_BLUE, 0, 0, 1000)
            curses.init_color(self.COLOR_RED, 1000, 0, 0)
            curses.init_color(self.COLOR_GREEN, 0, 1000, 0)

            # this will remove flicker, but gives boring colors
            '''
            self.COLOR_BLACK = curses.COLOR_BLACK
            self.COLOR_WHITE = curses.COLOR_WHITE
            self.COLOR_BLUE = curses.COLOR_BLUE
            self.COLOR_RED = curses.COLOR_RED
            self.COLOR_GREEN = curses.COLOR_GREEN
            '''

            for i in xrange(0, self.GRAYS):
                curses.init_color(
                        self.GRAY_BASE + i,
                        i * 1000 / (self.GRAYS - 1),
                        i * 1000 / (self.GRAYS - 1),
                        i * 1000 / (self.GRAYS - 1)
                        )
                curses.init_pair(
                        self.GRAY_BASE + i,
                        self.GRAY_BASE + i,
                        self.COLOR_BLACK
                        )

        else:
            self.COLOR_BLACK = curses.COLOR_BLACK
            self.COLOR_WHITE = curses.COLOR_WHITE
            self.COLOR_BLUE = curses.COLOR_BLUE
            self.COLOR_RED = curses.COLOR_RED
            self.COLOR_GREEN = curses.COLOR_GREEN

            for i in xrange(0, self.GRAYS):
                curses.init_pair(
                        self.GRAY_BASE + i,
                        self.COLOR_WHITE,
                        self.COLOR_BLACK
                        )

        curses.init_pair(self.BLACK, self.COLOR_BLACK, self.COLOR_BLACK)
        curses.init_pair(self.WHITE, self.COLOR_WHITE, self.COLOR_BLACK)
        curses.init_pair(self.BLUE, self.COLOR_BLUE, self.COLOR_BLACK)
        curses.init_pair(self.RED, self.COLOR_RED, self.COLOR_BLACK)
        curses.init_pair(self.GREEN, self.COLOR_GREEN, self.COLOR_BLACK)

    def gray(self, scale):
        if curses.can_change_color():
            return curses.color_pair(self.GRAY_BASE + int(round(scale * (self.GRAYS - 1))))
        else:
            return curses.color_pair(self.WHITE)

    def box(self, window, x, y, w, h, color):
        for i in xrange(1, w - 1):
            window.addch(y, x + i, curses.ACS_HLINE, color)
            window.addch(y + h - 1, x + i, curses.ACS_HLINE, color)
        for i in xrange(1, h - 1):
            window.addch(y + i, x, curses.ACS_VLINE, color)
            window.addch(y + i, x + w - 1, curses.ACS_VLINE, color)
        window.addch(y, x, curses.ACS_ULCORNER, color)
        window.addch(y, x + w - 1, curses.ACS_URCORNER, color)
        window.addch(y + h - 1, x, curses.ACS_LLCORNER, color)
        window.addch(y + h - 1, x + w - 1, curses.ACS_LRCORNER, color)

    def bracket(self, window, x, y, h, color):
        for i in xrange(1, h - 1):
            window.addch(y + i, x, curses.ACS_VLINE, color)
        window.addch(y, x, curses.ACS_ULCORNER, color)
        window.addch(y + h - 1, x, curses.ACS_LLCORNER, color)

    def vaddstr(self, window, x, y, s, color):
        for i in xrange(0, len(s)):
            window.addch(y + i, x, s[i], color)

    def draw(self):
        try:
            self.stdscr.erase()

            # constants
            left = self.sx + self.INDENT
            top = self.sy
            top_bracket_height = self.T.IL
            top_bracket_middle = self.T.IL / 2
            mne_width = 10
            op_width = 45
            raw_width = (16*2)

            # render log bracket
            self.bracket(self.stdscr, left - 1, top, top_bracket_height + 2, self.gray(1))

            # render logo
            self.vaddstr(self.stdscr, left - 3, top + top_bracket_middle - 5, "sand", self.gray(.2))
            self.vaddstr(self.stdscr, left - 3, top + top_bracket_middle + 5, "sifter", self.gray(.2))

            # refresh instruction log
            synth_insn = cstr2py(self.T.r.raw_insn)
            (mnemonic, op_str, size) = self.disas(synth_insn)
            self.T.il.append(
                    (
                        mnemonic,
                        op_str,
                        self.T.r.length,
                        "%s" % hexlify(synth_insn)
                    )
                )

            # render instruction log
            try:
                for (i, r) in enumerate(self.T.il):
                    line = i + self.T.IL - len(self.T.il)
                    (mnemonic, op_str, length, raw) = r
                    if i == len(self.T.il) - 1:
                        # latest instruction
                        # mnemonic
                        self.stdscr.addstr(
                                top + 1 + line,
                                left,
                                "%*s " % (mne_width, mnemonic),
                                self.gray(1)
                                )
                        # operands
                        self.stdscr.addstr(
                                top + 1 + line,
                                left + (mne_width + 1),
                                "%-*s " % (op_width, op_str),
                                curses.color_pair(self.BLUE)
                                )
                        # bytes
                        if self.maxx > left + (mne_width + 1) + (op_width + 1) + (raw_width + 1):
                            self.stdscr.addstr(
                                    top + 1 + line,
                                    left + (mne_width + 1) + (op_width + 1),
                                    "%s" % raw[0:length * 2],
                                    self.gray(.9)
                                    )
                            self.stdscr.addstr(
                                    top + 1 +line,
                                    left + (mne_width + 1) + (op_width + 1) + length * 2,
                                    "%s" % raw[length * 2:raw_width],
                                    self.gray(.3)
                                    )
                    else:
                        # previous instructions
                        # mnemonic, operands
                        self.stdscr.addstr(
                                top + 1 + line,
                                left,
                                "%*s %-*s" % (mne_width, mnemonic, op_width, op_str), 
                                self.gray(.5)
                                )
                        # bytes
                        if self.maxx > left + (mne_width + 1) + (op_width + 1) + (raw_width + 1):
                            self.stdscr.addstr(
                                    top + 1 + line,
                                    left + (mne_width + 1) + (op_width + 1),
                                    "%s" % raw[0:length * 2],
                                    self.gray(.3)
                                    )
                            self.stdscr.addstr(
                                    top + 1 + line,
                                    left + (mne_width + 1) + (op_width + 1) + length * 2,
                                    "%s" % raw[length * 2:raw_width],
                                    self.gray(.1)
                                    )
            except RuntimeError:
                # probably the deque was modified by the poller
                pass

            # rate calculation
            self.delta_log.append(self.T.ic - self.last_ins_count)
            self.last_ins_count = self.T.ic
            ctime = time.time()
            self.time_log.append(ctime - self.last_time)
            self.last_time = ctime
            rate = int(sum(self.delta_log)/sum(self.time_log))

            # render timestamp
            if self.maxx > left + (mne_width + 1) + (op_width + 1) + (raw_width + 1):
                self.vaddstr(
                        self.stdscr,
                        left + (mne_width + 1) + (op_width + 1) + (raw_width + 1),
                        top + 1,
                        self.T.elapsed(),
                        self.gray(.5)
                        )

            # render injection settings
            self.stdscr.addstr(top + 1, left - 8, "%d" % self.injector.settings.root, self.gray(.1))
            self.stdscr.addstr(top + 1, left - 7, "%s" % arch, self.gray(.1))
            self.stdscr.addstr(top + 1, left - 3, "%c" % self.injector.settings.synth_mode, self.gray(.5))

            # render injection results
            self.stdscr.addstr(top + top_bracket_middle, left - 6, "v:", self.gray(.5))
            self.stdscr.addstr(top + top_bracket_middle, left - 4, "%2x" % self.T.r.valid)
            self.stdscr.addstr(top + top_bracket_middle + 1, left - 6, "l:", self.gray(.5))
            self.stdscr.addstr(top + top_bracket_middle + 1, left - 4, "%2x" % self.T.r.length)
            self.stdscr.addstr(top + top_bracket_middle + 2, left - 6, "s:", self.gray(.5))
            self.stdscr.addstr(top + top_bracket_middle + 2, left - 4, "%2x" % self.T.r.signum)
            self.stdscr.addstr(top + top_bracket_middle + 3, left - 6, "c:", self.gray(.5))
            self.stdscr.addstr(top + top_bracket_middle + 3, left - 4, "%2x" % self.T.r.sicode)
            
            # render instruction count
            self.stdscr.addstr(top + top_bracket_height + 2, left, "#", self.gray(.5))
            self.stdscr.addstr(top + top_bracket_height + 2, left + 2, 
                    "%s" % (int_to_comma(self.T.ic)), self.gray(1))
            # render rate
            self.stdscr.addstr(top + top_bracket_height + 3, left, 
                    "  %d/s%s" % (rate, " " * min(rate / self.RATE_FACTOR, 100)), curses.A_REVERSE)
            # render artifact count
            self.stdscr.addstr(top + top_bracket_height + 4, left, "#", self.gray(.5))
            self.stdscr.addstr(top + top_bracket_height + 4, left + 2, 
                    "%s" % (int_to_comma(self.T.ac)), curses.color_pair(self.RED))

            # render artifact log
            if self.maxy >= top + top_bracket_height + 5 + self.T.UL + 2:

                # render artifact bracket
                self.bracket(self.stdscr, left - 1, top + top_bracket_height + 5, self.T.UL + 2, self.gray(1))

                # render artifacts
                try:
                    for (i, r) in enumerate(self.T.al):
                        y = top_bracket_height + 5 + i
                        insn_hex = hexlify(cstr2py(r.raw_insn))

                        # unexplainable hack to remove some of the unexplainable
                        # flicker on my console.  a bug in ncurses?  doesn't
                        # happen if using curses.COLOR_RED instead of a custom
                        # red.  doesn't happen if using a new random string each
                        # time; doesn't happen if using a constant string each
                        # time.  only happens with the specific implementation below.
						#TODO: on systems with limited color settings, this
						# makes the background look like random characters
                        random_string = ("%02x" % random.randint(0,100)) * (raw_width-2)
                        self.stdscr.addstr(top + 1 + y, left, random_string, curses.color_pair(self.BLACK))

                        self.stdscr.addstr(top + 1 + y, left + 1, 
                                "%s" % insn_hex[0:r.length * 2], curses.color_pair(self.RED))
                        self.stdscr.addstr(top + 1 + y, left + 1 + r.length * 2, 
                                "%s" % insn_hex[r.length * 2:raw_width], self.gray(.25))
                except RuntimeError:
                    # probably the deque was modified by the poller
                    pass

            self.stdscr.refresh()
        except curses.error:
            pass

    def start(self):
        self.gui_thread = threading.Thread(target=self.render)
        self.gui_thread.start()

    def stop(self):
        self.gui_thread.join()

    def checkkey(self):
        c = self.stdscr.getch()
        if c == ord('p'):
            self.ts.pause = not self.ts.pause
        elif c == ord('q'):
            self.ts.run = False
        elif c == ord('m'):
            self.ts.pause = True
            time.sleep(.1)
            self.injector.stop()
            self.injector.settings.increment_synth_mode()
            self.injector.start()
            self.ts.pause = False

    def render(self):
        while self.ts.run:
            while self.ts.pause:
                self.checkkey()
                time.sleep(.1)

            (self.maxy,self.maxx) = self.stdscr.getmaxyx()

            self.sx = 1
            self.sy = max((self.maxy + 1 - (self.T.IL + self.T.UL + 5 + 2))/2, 0)

            self.checkkey()

            synth_insn = cstr2py(self.T.r.raw_insn)

            if synth_insn and not self.ts.pause:
                self.draw()

            if self.do_tick:
                self.ticks = self.ticks + 1
                if self.ticks & self.TICK_MASK == 0:
                    with open(TICK, 'w') as f:
                        f.write("%s" % hexlify(synth_insn))

            time.sleep(self.TIME_SLICE)

def get_cpu_info():
    with open("/proc/cpuinfo", "r") as f:
        cpu = [l.strip() for l in f.readlines()[:7]]
    return cpu

def dump_artifacts(r, injector, command_line):
    global arch
    tee = Tee(LOG, "w")
    tee.write("#\n")
    tee.write("# %s\n" % command_line)
    tee.write("# %s\n" % injector.command)
    tee.write("#\n")
    tee.write("# insn tested: %d\n" % r.ic)
    tee.write("# artf found:  %d\n" % r.ac)
    tee.write("# runtime:     %s\n" % r.elapsed())
    tee.write("# seed:        %d\n" % injector.settings.seed)
    tee.write("# arch:        %s\n" % arch)
    tee.write("# date:        %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
    tee.write("#\n")
    tee.write("# cpu:\n")

    cpu = get_cpu_info()
    for l in cpu:
        tee.write("# %s\n" % l) 

    tee.write("# %s  v  l  s  c\n" % (" " * 28))
    for k in sorted(list(r.ad)):
        v = r.ad[k]
        tee.write(result_string(k, v))

def cleanup(gui, poll, injector, ts, tests, command_line, args):
    ts.run = False
    if gui:
        gui.stop()
    if poll:
        poll.stop()
    if injector:
        injector.stop()

    '''
    # doesn't work
    if gui:
        for (i, c) in enumerate(gui.orig_colors):
            curses.init_color(i, c[0], c[1], c[2])
    '''

    curses.nocbreak();
    curses.echo()
    curses.endwin()

    dump_artifacts(tests, injector, command_line)

    if args.save:
        with open(LAST, "w") as f:
            f.write(hexlify(cstr2py(tests.r.raw_insn)))

    sys.exit(0)

def main():
    global arch
    def exit_handler(signal, frame):
        cleanup(gui, poll, injector, ts, tests, command_line, args)

    injector = None
    poll = None
    gui = None

    command_line = " ".join(sys.argv)

    parser = argparse.ArgumentParser()
    parser.add_argument("--len", action="store_true", default=False,
            help="search for length differences in all instructions (instructions\
            that executed differently than the disassembler expected, or did not\
            exist when the disassembler expected them to)"
            )
    parser.add_argument("--dis", action="store_true", default=False,
            help="search for length differences in valid instructions (instructions\
            that executed differently than the disassembler expected)"
            )
    parser.add_argument("--unk", action="store_true", default=False,
            help="search for unknown instructions (instructions that the\
            disassembler doesn't know about but successfully execute)"
            )
    parser.add_argument("--ill", action="store_true", default=False,
            help="the inverse of --unk, search for invalid disassemblies\
            (instructions that do not successfully execute but that the\
            disassembler acknowledges)"
            )
    parser.add_argument("--tick", action="store_true", default=False,
            help="periodically write the current instruction to disk"
            )
    parser.add_argument("--save", action="store_true", default=False,
            help="save search progress on exit"
            )
    parser.add_argument("--resume", action="store_true", default=False,
            help="resume search from last saved state"
            )
    parser.add_argument("--sync", action="store_true", default=False,
            help="write search results to disk as they are found"
            )
    parser.add_argument("--low-mem", action="store_true", default=False,
            help="do not store results in memory"
            )
    parser.add_argument("injector_args", nargs=argparse.REMAINDER)

    args = parser.parse_args()

    injector_args = args.injector_args
    if "--" in injector_args: injector_args.remove("--")

    if not args.len and not args.unk and not args.dis and not args.ill:
        print "warning: no search type (--len, --unk, --dis, --ill) specified, results will not be recorded."
        raw_input()

    if args.resume:
        if "-i" in injector_args:
            print "--resume is incompatible with -i"
            sys.exit(1)

        if os.path.exists(LAST):
            with open(LAST, "r") as f:
                insn = f.read()
                injector_args.extend(['-i',insn])
        else:
            print "no resume file found"
            sys.exit(1)

    if not os.path.exists(OUTPUT):
        os.makedirs(OUTPUT)

    injector_bitness, errors = \
        subprocess.Popen(
                ['file', INJECTOR],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
                ).communicate()
    arch = re.search(r".*(..)-bit.*", injector_bitness).group(1)

    ts = ThreadState()
    signal.signal(signal.SIGINT, exit_handler)

    settings = Settings(args.injector_args)

    tests = Tests()

    injector = Injector(settings)
    injector.start()

    poll = Poll(ts, injector, tests, command_line, args.sync, 
                    args.low_mem, args.unk, args.len, args.dis, args.ill)
    poll.start()

    gui = Gui(ts, injector, tests, args.tick)
    gui.start()

    while ts.run:
        time.sleep(.1)

    cleanup(gui, poll, injector, ts, tests, command_line, args)

if __name__ == '__main__':
    main()

import curses
import locale

class Box:
    def __init__(self, gui, window, x, y, w, h, color):
        self.gui = gui
        self.window = window
        self.x = x
        self.y = y
        self.w = w
        self.h = h
        self.color = color

    def draw(self):
        self.gui.box(self.window, self.x, self.y, self.w, self.h, self.color)

class TextBox:
    def __init__(self, gui, window, x, y, w, h, color, text, text_color, selected_color):

        self.gui = gui
        self.window = window

        self.x = x
        self.y = y
        self.w = w
        self.h = h

        self.scroll_index = 0
        self.selected_index = 0
        self.text = text

        self.text_color = text_color
        self.color = color
        self.selected_color = selected_color

    def scroll_up(self):
        if self.selected_index > 0:
            self.selected_index = self.selected_index - 1
        if self.selected_index < self.scroll_index:
            self.scroll_index = self.scroll_index - 1
        self.draw()

    def scroll_down(self):
        if self.selected_index < len(self.text) - 1:
            self.selected_index = self.selected_index + 1
        if self.selected_index > self.scroll_index + (self.h - 2) - 1:
            self.scroll_index = self.scroll_index + 1
        self.draw()

    def at_top(self):
		return self.selected_index == 0

    def at_bottom(self):
		return self.selected_index == len(self.text) - 1

    def scroll_top(self):
		self.selected_index = 0
		self.scroll_index = 0
		self.draw()

    def scroll_bottom(self):
		self.selected_index = len(self.text) - 1
		self.scroll_index = len(self.text) - (self.h - 2)
		self.scroll_index = self.scroll_index if self.scroll_index > 0 else 0
		self.draw()

    def draw(self):
        self.gui.box(self.window, self.x, self.y, self.w, self.h, self.color)
        for (i, l) in enumerate(self.text[self.scroll_index:self.scroll_index + self.h - 2]):
            if len(l) > self.w - 2:
                l = l[:self.w - 5] + "..."
            l = l.ljust(self.w - 2)
            self.window.addstr(self.y + 1 + i, self.x + 1, l, self.text_color if
                    self.selected_index != self.scroll_index + i else self.selected_color)
        for j in xrange(i + 1, self.h - 2):
            self.window.addstr(self.y + 1 + j, self.x + 1, " " * (self.w - 2), self.text_color if
                    self.selected_index != self.scroll_index + j else self.selected_color)
        self.gui.vscrollbar(self.window, self.x + self.w, self.y, self.h,
                self.selected_index / float(len(self.text)), self.gui.gray(1))

class Gui:
    GRAY_BASE = 50
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

    def __init__(self, no_delay=True):
        self.start(no_delay)

    def refresh(self):
        self.window.refresh()

    def start(self, no_delay):
        self.window = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)
        self.window.nodelay(no_delay)
        self.init_colors()
        self.window.bkgd(curses.color_pair(self.WHITE))
        locale.setlocale(locale.LC_ALL, '')    # set your locale
        self.code = locale.getpreferredencoding()

    def stop(self):
        curses.nocbreak();
        curses.echo()
        curses.endwin()

    def get_key(self):
        return self.window.getch()

    def init_colors(self):

        if curses.has_colors() and curses.can_change_color():
            curses.init_color(self.COLOR_BLACK, 0, 0, 0)
            curses.init_color(self.COLOR_WHITE, 1000, 1000, 1000)
            curses.init_color(self.COLOR_BLUE, 0, 0, 1000)
            curses.init_color(self.COLOR_RED, 1000, 0, 0)
            curses.init_color(self.COLOR_GREEN, 0, 1000, 0)

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

    def vscrollbar(self, window, x, y, height, progress, color):
        if height < 3:
            return
        self.vaddstr(window, x, y, "-" + " " * (height - 2) + "-", color)
        window.addch(int(y + 1 + progress * (height - 2)), x, "|", color)

    def hscrollbar(self, window, x, y, width, color):
        window.addstr(y, x, "}", color)
        window.addstr(y + height - 1, x, '}', color)
        window.addch(y, int(x + 1 + progress * (width - 2)), curses.ACS_BLOCK, color)


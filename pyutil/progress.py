import sys

PROGRESS_BAR_WIDTH = 40
PROGRESS_LINE_MAX = 1024

def progress(i, n, text="", refresh=1, unknown=False):
    if not n:
        n = 1
        i = 1
    if refresh < 1:
        refresh = 1
    if i % refresh == 0 or i == n:
        c = (i * PROGRESS_BAR_WIDTH / n) % (PROGRESS_BAR_WIDTH + 1)
        if unknown:
            bar = " " * (c - 1) + "=" * (1 if c else 0) + " " * (PROGRESS_BAR_WIDTH-c)
            percent = ""
        else:
            bar = "=" * c + " " * (PROGRESS_BAR_WIDTH-c)
            percent = "%5.1f%%" % (float(i) * 100 / n)
        sys.stdout.write("[%s] %s %s   " % ( \
                bar,
                percent,
                "- %s" % text if text else ""
                ))
        sys.stdout.flush()
        sys.stdout.write("\b" * PROGRESS_LINE_MAX)
        if not unknown and i == n:
            sys.stdout.write("\n")

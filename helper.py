#!/usr/bin/python3
#
# This file is part of libptmalloc.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>

class logger:
    def logmsg(s, debug=True):
        if not debug:
            return
        if type(s) == str:
            print("[helper] " + s)
        else:
            print(s)

# Taken from gef. Let's us see proper backtraces from python exceptions
def show_last_exception():
    PYTHON_MAJOR = sys.version_info[0]
    horizontal_line = "-"
    right_arrow = "->"
    down_arrow = "\\->"

    print("")
    exc_type, exc_value, exc_traceback = sys.exc_info()
    print(" Exception raised ".center(80, horizontal_line))
    print("{}: {}".format(exc_type.__name__, exc_value))
    print(" Detailed stacktrace ".center(80, horizontal_line))
    for fs in traceback.extract_tb(exc_traceback)[::-1]:
        if PYTHON_MAJOR==2:
            filename, lineno, method, code = fs
        else:
            try:
                filename, lineno, method, code = fs.filename, fs.lineno, fs.name, fs.line
            except:
                filename, lineno, method, code = fs

        print("""{} File "{}", line {:d}, in {}()""".format(down_arrow, filename,
                                                            lineno, method))
        print("   {}    {}".format(right_arrow, code))

def is_ascii(s):
    return all(c < 128 and c > 1 for c in s)
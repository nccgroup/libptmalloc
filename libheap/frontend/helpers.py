import sys
import traceback


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
        if PYTHON_MAJOR == 2:
            filename, lineno, method, code = fs
        else:
            try:
                filename, lineno, method, code = (
                    fs.filename,
                    fs.lineno,
                    fs.name,
                    fs.line,
                )
            except:
                filename, lineno, method, code = fs

        print(
            """{} File "{}", line {:d}, in {}()""".format(
                down_arrow, filename, lineno, method
            )
        )
        print("   {}    {}".format(right_arrow, code))


def is_ascii(s):
    return all(c < 128 and c > 1 for c in s)


def string_to_int(num):
    """Convert an integer or hex integer string to an int
    :returns: converted integer

    especially helpful for using ArgumentParser()
    """
    if num.find("0x") != -1:
        return int(num, 16)
    else:
        return int(num)

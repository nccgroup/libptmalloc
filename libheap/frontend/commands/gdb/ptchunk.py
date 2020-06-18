from __future__ import print_function

import argparse
import sys

import libheap.frontend.helpers as h
from libheap.frontend.printutils import print_error, print_header
from libheap.ptmalloc.malloc_state import malloc_state
from libheap.ptmalloc.ptmalloc import ptmalloc

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")


class ptchunk(gdb.Command):
    """libheap command help listing"""

    def __init__(self, debugger=None, version=None):
        super(ptchunk, self).__init__("ptchunk", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

        if debugger is not None:
            self.dbg = debugger
        else:
            print_error("Please specify a debugger")
            raise Exception("sys.exit()")

        self.version = version

    def help(self):
        """print the command usage """

        print(
            "usage: ptchunk [-v] [-f] [-x] [-n] [-p <offset>] [-c <count>] [-s <val>] [--depth <depth>] <addr>"
        )
        print(" -v      use verbose output (multiples for more verbosity)")
        print(" -f      use <addr> explicitly, rather than be smart")
        print(" -x      hexdump the chunk contents")
        print(" -m      max bytes to dump with -x")
        print(" -c      number of chunks to print")
        print(" -s      search pattern when print chunks")
        print(" --depth how far into each chunk to search")
        print(" -d      debug and force printing stuff")
        print(" -n      do not output the trailing newline (summary representation)")
        print(" -p      print data inside at given offset (summary representation)")
        print(" <addr>  a ptmalloc chunk header")
        print("Flag legend: P=PREV_INUSE, M=MMAPPED, N=NON_MAIN_ARENA")

    def invoke(self, arg, from_tty):
        try:
            self.invoke_(arg, from_tty)
        except Exception:
            h.show_last_exception()

    def parse_address(self, addresses):
        """Parse one or more addresses or gdb variables.

        :address: an address string containing hex, int, or variable
        :returns: the resolved addresses as integers

        It this should be able to handle: hex, decimal, program variables
        without &, program variables with &, gdb variables starting with $,
        basic addition and subtraction of variables, etc
        """
        resolved = []
        if type(addresses) != list:
            addresses = [addresses]
        for item in addresses:
            addr = None
            try:
                addr = self.dbg.parse_variable(item)
            except:
                try:
                    addr = self.dbg.parse_variable("&" + item)
                except:
                    print(f"ERROR: Unable to parse {item}")
                    continue
            if addr is not None:
                resolved.append(addr)
        return resolved

    def invoke_(self, arg, from_tty):
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument(
            "-v", "--verbose", dest="verbose", action="count", default=0,
        )
        parser.add_argument(
            "-h", "--help", dest="help", action="store_true", default=False,
        )
        parser.add_argument(
            "-f", dest="force", action="store_true", default=False,
        )
        parser.add_argument(
            "-x", "--hexdump", dest="hexdump", action="store_true", default=False,
        )
        parser.add_argument(
            "-d", "--debug", dest="debug", action="store_true", default=False,
        )
        parser.add_argument(
            "-c", "--count", dest="count", type=int, default=1,
        )
        parser.add_argument(
            "-m", "--maxbytes", dest="maxbytes", type=str, default=None,
        )
        parser.add_argument(
            "-n", dest="no_newline", action="store_true", default=False,
        )
        parser.add_argument(
            "-p", dest="print_offset", type=int, default=0,
        )
        parser.add_argument(
            "-s", dest="search_value", type=str, default=None,
        )
        parser.add_argument(
            "--depth", dest="depth", type=int, default=0,
        )
        parser.add_argument(
            "addresses", nargs="+", default=None,
        )

        args = parser.parse_args(arg.split())
        if args.help:
            self.help()
            return

        addresses = []
        if not args.addresses:
            print("WARNING: No address supplied?")
            self.help()
            return
        else:
            addresses = self.parse_address(args.addresses)
            if len(addresses) == 0:
                self.pt.logmsg("WARNING: No valid address supplied")
                self.help()
                return

        ptm = ptmalloc(self.dbg)

        for address in addresses:
            print(hex(address))

        # XXX
        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

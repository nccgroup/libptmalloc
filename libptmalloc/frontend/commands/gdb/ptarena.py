from __future__ import print_function

import argparse
import binascii
import struct
import sys
import logging
import importlib

import libptmalloc.frontend.printutils as pu
importlib.reload(pu)
import libptmalloc.ptmalloc.malloc_chunk as mc
importlib.reload(mc)
import libptmalloc.ptmalloc.malloc_state as ms
importlib.reload(ms)
import libptmalloc.ptmalloc.ptmalloc as pt
importlib.reload(pt)
import libptmalloc.frontend.helpers as h
importlib.reload(h)
import libptmalloc.frontend.commands.gdb.ptcmd as ptcmd # no reload on purpose

log = logging.getLogger("libptmalloc")
log.trace("ptarena.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")  

class ptarena(ptcmd.ptcmd):
    """Command to print information about arena(s) represented by the malloc_state structure
    """

    def __init__(self, ptm):
        log.debug("ptarena.__init__()")
        super(ptarena, self).__init__(ptm, "ptarena")

        self.parser = argparse.ArgumentParser(
            description="""Print arena(s) information

An arena is also known as an mstate.
Analyze the malloc_state structure's fields.""", 
            add_help=False, 
            formatter_class=argparse.RawTextHelpFormatter,
            epilog='NOTE: Last defined mstate will be cached for future use')
        self.parser.add_argument(
            "-v", "--verbose", dest="verbose", action="count", default=0,
            help="Use verbose output (multiple for more verbosity)"
        )
        self.parser.add_argument(
            "-h", "--help", dest="help", action="store_true", default=False,
            help="Show this help"
        )
        self.parser.add_argument(
            "-l", dest="list", action="store_true", default=False,
            help="List the arenas addresses only"
        )
        self.parser.add_argument(
            "--use-cache", dest="use_cache", action="store_true", default=False,
            help="Do not fetch mstate data if you know they haven't changed since last time they were cached"
        )
        self.parser.add_argument(
            "address", default=None, nargs="?", type=h.string_to_int,
            help="A malloc_mstate struct address. Optional with cached mstate"
        )
        # allows to enable a different log level during development/debugging
        self.parser.add_argument(
            "--loglevel", dest="loglevel", default=None,
            help=argparse.SUPPRESS
        )

    @h.catch_exceptions
    @ptcmd.ptcmd.init_and_cleanup
    def invoke(self, arg, from_tty):
        """Inherited from gdb.Command
        See https://sourceware.org/gdb/current/onlinedocs/gdb/Commands-In-Python.html
        """

        log.debug("ptarena.invoke()")

        self.cache.update_arena(self.args.address, show_status=True, use_cache=self.args.use_cache)

        if self.args.list:
            self.list_arenas()
            return

        if self.args.verbose == 0:
            print(self.cache.mstate)
        elif self.args.verbose >= 1:
            print(self.cache.mstate.to_string(self.args.verbose))

    def list_arenas(self):
        """List the arena addresses only
        """

        mstate = self.cache.mstate

        if mstate.next == 0:
            print("No arenas could be correctly guessed. Wrong glibc version configured?")
            print("Nothing was found at {0:#x}".format(mstate.address))
            return

        print("Arena(s) found:", end="\n")
        print("  arena @ ", end="")
        pu.print_header("{:#x}".format(int(mstate.address)), end="\n")

        if mstate.address != mstate.next:
            # we have more than one arena

            curr_arena = ms.malloc_state(
                self.ptm, mstate.next, debugger=self.dbg, version=self.version
            )

            while mstate.address != curr_arena.address:
                print("  arena @ ", end="")
                pu.print_header("{:#x}".format(int(curr_arena.address)), end="\n")
                curr_arena = ms.malloc_state(
                    self.ptm, curr_arena.next, debugger=self.dbg, version=self.version
                )

                if curr_arena.address == 0:
                    pu.print_error("No arenas could be correctly found.")
                    break  # breaking infinite loop
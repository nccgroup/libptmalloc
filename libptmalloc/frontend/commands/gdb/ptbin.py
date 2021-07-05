# -*- coding: future_fstrings -*-
from __future__ import print_function

import argparse
import struct
import sys
import logging

from libptmalloc.frontend import printutils as pu
from libptmalloc.ptmalloc import malloc_chunk as mc
from libptmalloc.ptmalloc import ptmalloc as pt
from libptmalloc.frontend import helpers as h
from libptmalloc.frontend.commands.gdb import ptfree
from libptmalloc.frontend.commands.gdb import ptchunk
from libptmalloc.frontend.commands.gdb import ptcmd

log = logging.getLogger("libptmalloc")
log.trace("ptbin.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")

class ptbin(ptcmd.ptcmd):
    """Command to walk and print the unsorted/small/large bins

    Also see ptchunk description"""

    def __init__(self, ptm):
        log.debug("ptbin.__init__()")
        super(ptbin, self).__init__(ptm, "ptbin")

        self.parser = argparse.ArgumentParser(
            description="""Print unsorted/small/large bins information

All these bins are implemented in the malloc_state.bins[] member. 
The unsorted bin is index 0, the small bins are indexes 1-62 and above 63 are large bins.""", 
            add_help=False,
            formatter_class=argparse.RawTextHelpFormatter,
        )
        self.parser.add_argument(
            "-i", "--index", dest="index", default=None, type=int,
            help="Index to the bin to show (0 to 126)"
        )
        self.parser.add_argument(
            "-b", "--bin-size", dest="size", default=None, type=h.string_to_int,
            help="Small/large bin size to show"
        )
        # "ptchunk" also has this argument but default and help is different
        self.parser.add_argument(
            "-c", "--count", dest="count", type=h.check_positive, default=None,
            help="Maximum number of chunks to print in each bin"
        )
        # other arguments are implemented in the "ptchunk" command
        # and will be shown after the above
        ptchunk.ptchunk.add_arguments(self)

    @h.catch_exceptions
    @ptcmd.ptcmd.init_and_cleanup
    def invoke(self, arg, from_tty):
        """Inherited from gdb.Command
        See https://sourceware.org/gdb/current/onlinedocs/gdb/Commands-In-Python.html
        """

        log.debug("ptbin.invoke()")

        self.cache.update_arena(show_status=self.args.debug)
        mstate = self.cache.mstate
        # This is required by ptchunk.parse_many()
        self.cache.update_param(show_status=self.args.debug, use_cache=self.args.use_cache)

        # This is required by show_one_bin(), see description
        self.args.real_count = self.args.count

        if self.args.index != None and self.args.size != None:
            pu.print_error("Only one of -i and -s can be provided")
            return

        if self.args.index != None or self.args.size != None:
            ptfree.ptfree.show_one_bin(self, "regular", index=self.args.index, size=self.args.size, use_cache=self.args.use_cache)
        else:
            self.show_bins(mstate)

    def show_bins(self, mstate, use_cache=False):
        """Browse the malloc_state.bins[] fd/bk entries and show how many chunks there is.
        It does not show the actual chunks in each bin though
        """

        # We update the cache here so we can see the status before we print
        # the title below. Hence we pass use_cache=False on bins_to_string() call
        self.ptm.cache.update_bins(show_status=self.args.debug, use_cache=use_cache)

        verbose = self.args.verbose
        sb_base = mstate.address + mstate.bins_offset

        pu.print_title("Unsorted/small/large bins in malloc_state @ {:#x}".format(mstate.address), end="")
        txt = mstate.bins_to_string(verbose=self.args.verbose+1, use_cache=False)
        print(txt)
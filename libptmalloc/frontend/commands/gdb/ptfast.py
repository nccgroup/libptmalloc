# -*- coding: future_fstrings -*-
from __future__ import print_function

import argparse
import struct
import sys
import logging

from libptmalloc.frontend import printutils as pu
from libptmalloc.ptmalloc import malloc_chunk as mc
from libptmalloc.ptmalloc import malloc_state as ms
from libptmalloc.ptmalloc import ptmalloc as pt
from libptmalloc.frontend import helpers as h
from libptmalloc.frontend.commands.gdb import ptchunk
from libptmalloc.frontend.commands.gdb import ptfree
from libptmalloc.frontend.commands.gdb import ptcmd

log = logging.getLogger("libptmalloc")
log.trace("ptfast.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")

class ptfast(ptcmd.ptcmd):
    """Command to walk and print the fast bins

    Also see ptchunk description"""

    def __init__(self, ptm):
        log.debug("ptfast.__init__()")
        super(ptfast, self).__init__(ptm, "ptfast")

        self.parser = argparse.ArgumentParser(
            description="""Print fast bins information

They are implemented in the malloc_state.fastbinsY[] member.""", 
            add_help=False,
            formatter_class=argparse.RawTextHelpFormatter,
        )
        self.parser.add_argument(
            "address", default=None, nargs="?", type=h.string_to_int,
            help="An optional arena address"
        )
        self.parser.add_argument(
            "-i", "--index", dest="index", default=None, type=int,
            help="Index to the fast bin to show (0 to 9)"
        )
        self.parser.add_argument(
            "-b", "--bin-size", dest="size", default=None, type=h.string_to_int,
            help="Fast bin size to show"
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

        log.debug("ptfast.invoke()")

        self.cache.update_arena(self.args.address, show_status=self.args.debug, use_cache=self.args.use_cache)
        mstate = self.cache.mstate
        # This is required by ptchunk.parse_many()
        self.cache.update_param(show_status=self.args.debug, use_cache=self.args.use_cache)

        # This is required by show_one_bin(), see description
        self.args.real_count = self.args.count

        if self.args.index != None and self.args.size != None:
            pu.print_error("Only one of -i and -s can be provided")
            return

        if self.args.index != None or self.args.size != None:
            ptfree.ptfree.show_one_bin(self, "fast", index=self.args.index, size=self.args.size, use_cache=self.args.use_cache)
        else:
            self.show_fastbins(mstate, use_cache=self.args.use_cache)

    def show_fastbins(self, mstate, use_cache=False):
        """Browse the malloc_state.fastbinsY[] fd entries and show how many chunks there is.
        It does not show the actual chunks in each bin though
        """

        # We update the cache here so we can see the status before we print
        # the title below. Hence we pass use_cache=False on fastbins_to_string() call
        self.ptm.cache.update_fast_bins(show_status=self.args.debug, use_cache=use_cache)

        pu.print_title("Fast bins in malloc_state @ {:#x}".format(mstate.address), end="")
        txt = mstate.fastbins_to_string(verbose=self.args.verbose+1, use_cache=False)
        print(txt)

    # XXX - support the "size" argument if needed
    @staticmethod
    def is_in_fastbin(address, ptm, dbg=None, size=None, index=None, use_cache=False):
        """Check if a particular chunk's address is in one or all fast bins"""
        
        if index != None:
            ptm.cache.update_fast_bins(use_cache=use_cache, bins_list=[index])
            if address in ptm.cache.fast_bins[index]:
                return True
            else:
                return False
        else:
            ptm.cache.update_fast_bins(use_cache=use_cache)
            for i in range(0, ptm.NFASTBINS):
                if address in ptm.cache.fast_bins[i]:
                    return True
            return False
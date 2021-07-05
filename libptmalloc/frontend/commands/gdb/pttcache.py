# -*- coding: future_fstrings -*-
from __future__ import print_function

import argparse
import struct
import sys
import logging

from libptmalloc.frontend import printutils as pu
from libptmalloc.ptmalloc import ptmalloc as pt
from libptmalloc.frontend import helpers as h
from libptmalloc.ptmalloc import malloc_chunk as mc
from libptmalloc.frontend.commands.gdb import ptchunk
from libptmalloc.frontend.commands.gdb import ptfree
from libptmalloc.frontend.commands.gdb import ptcmd

log = logging.getLogger("libptmalloc")
log.trace("pttcache.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")

class pttcache(ptcmd.ptcmd):
    """Command to walk and print the tcache bins
    
    Also see ptchunk description"""

    def __init__(self, ptm):
        log.debug("pttcache.__init__()")
        super(pttcache, self).__init__(ptm, "pttcache")

        self.parser = argparse.ArgumentParser(
            description="""Print tcache bins information

All these bins are part of the tcache_perthread_struct structure. 
tcache is only available from glibc 2.26""", 
            add_help=False,
            formatter_class=argparse.RawTextHelpFormatter,
        )
        self.parser.add_argument(
            "address", default=None, nargs="?", type=h.string_to_int,
            help="An optional tcache address"
        )
        self.parser.add_argument(
            "-l", dest="list", action="store_true", default=False,
            help="List tcache(s)' addresses only"
        )
        self.parser.add_argument(
            "-i", "--index", dest="index", default=None, type=int,
            help="Index to the tcache bin to show (0 to 63)"
        )
        self.parser.add_argument(
            "-b", "--bin-size", dest="size", default=None, type=h.string_to_int,
            help="Tcache bin size to show"
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

        log.debug("pttcache.invoke()")

        if not self.ptm.is_tcache_enabled():
            print("tcache is currently disabled. Check glibc version or manually overide the tcache settings")
            return
        if not self.ptm.tcache_available:
            print("tcache is not currently available. Your target binary does not use threads to leverage tcache?")
            return

        self.cache.update_tcache(self.args.address, show_status=self.args.debug, use_cache=self.args.use_cache)
        # This is required by ptchunk.parse_many()
        self.cache.update_arena(show_status=self.args.debug, use_cache=self.args.use_cache)
        self.cache.update_param(show_status=self.args.debug, use_cache=self.args.use_cache)

        # This is required by show_one_bin(), see description
        self.args.real_count = self.args.count

        if self.args.list:
            self.list_tcaches()
            return

        if self.args.index != None and self.args.size != None:
            pu.print_error("Only one of -i and -s can be provided")
            return

        log.debug("tcache_address = 0x%x" % self.cache.tcache.address)
        if self.args.index == None and self.args.size == None:
            if self.args.verbose == 0:
                print(self.cache.tcache.to_summary_string())
            elif self.args.verbose == 1:
                print(self.cache.tcache)
            elif self.args.verbose == 2:
                print(self.cache.tcache.to_string(verbose=True))
        else:
            ptfree.ptfree.show_one_bin(self, "tcache", index=self.args.index, size=self.args.size, use_cache=self.args.use_cache)

    def list_tcaches(self):
        """List tcache addresses"""

        tcache = self.cache.tcache

        print("Tcache(s) found:", end="\n")
        print("  tcache @ ", end="")
        pu.print_header("{:#x}".format(int(tcache.address)), end="\n")

    # XXX - support the "size" argument if needed
    @staticmethod
    def is_in_tcache(address, ptm, dbg=None, size=None, index=None, use_cache=False):
        """Similar to ptfast.is_in_fastbin() but for tcache"""
        
        if not ptm.is_tcache_enabled() or not ptm.tcache_available:
            return False # address can't be in tcache bins if tcache is disabled globally :)

        if index != None:
            ptm.cache.update_tcache_bins(use_cache=use_cache, bins_list=[index])
            if address in ptm.cache.tcache_bins[index]:
                return True
            else:
                return False
        else:
            ptm.cache.update_tcache_bins(use_cache=use_cache)
            for i in range(0, ptm.TCACHE_MAX_BINS):
                if address in ptm.cache.tcache_bins[i]:
                    return True
            return False
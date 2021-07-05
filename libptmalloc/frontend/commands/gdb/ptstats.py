# -*- coding: future_fstrings -*-
from __future__ import print_function

import sys
import logging
import argparse

from libptmalloc.frontend import printutils as pu
from libptmalloc.ptmalloc import malloc_chunk as mc
from libptmalloc.ptmalloc import malloc_par as mp
from libptmalloc.ptmalloc import malloc_state as ms
from libptmalloc.ptmalloc import ptmalloc as pt
from libptmalloc.frontend import helpers as h
from libptmalloc.frontend.commands.gdb import ptcmd

log = logging.getLogger("libptmalloc")
log.trace("ptstats.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")

class ptstats(ptcmd.ptcmd):
    """Command to print general malloc stats, adapted from malloc.c mSTATs()"""

    def __init__(self, ptm):
        log.debug("ptstats.__init__()")
        super(ptstats, self).__init__(ptm, "ptstats")

        self.parser = argparse.ArgumentParser(
            description="""Print memory alloc statistics similar to malloc_stats(3)""", 
            add_help=False,
            formatter_class=argparse.RawTextHelpFormatter,
        )
        self.parser.add_argument(
            "-v", "--verbose", dest="verbose", action="count", default=0,
            help="Use verbose output (multiple for more verbosity)"
        )
        self.parser.add_argument(
            "-h", "--help", dest="help", action="store_true", default=False,
            help="Show this help"
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
    
        # We don't yet update the tcache, arena and param structs as well as the
        # tcache bins, tcache bins and unsorted/small/large bins
        # yet as we need to do it for every single arena so will do when browsing them
        self.show_stats()
    
    def show_stats(self):
        """Show a summary of the memory statistics
        """

        self.cache.update_arena(show_status=False)
        self.cache.update_param(show_status=False)
        self.cache.update_tcache(show_status=False)
        self.cache.update_tcache_bins(show_status=False)

        main_arena_address = self.cache.main_arena_address
        par = self.cache.par

        in_use_b = par.mmapped_mem
        avail_b = 0
        system_b = in_use_b

        pu.print_title("Malloc Stats", end="\n\n")

        arena = 0
        mstate = ms.malloc_state(
            self.ptm, main_arena_address, debugger=self.dbg, version=self.version
        )
        while 1:

            self.cache.update_arena(address=mstate.address, show_status=False)
            self.cache.update_fast_bins(show_status=False)
            self.cache.update_bins(show_status=False)

            if mstate.address == self.cache.main_arena_address:
                sbrk_base, _ = self.dbg.get_heap_address(par)
            else:
                sbrk_base = (mstate.address + mstate.size + self.ptm.MALLOC_ALIGN_MASK) & ~self.ptm.MALLOC_ALIGN_MASK

            avail = 0
            inuse = 0
            nblocks = 1
            addr = sbrk_base
            while True:
                p = mc.malloc_chunk(
                    self.ptm, 
                    addr, 
                    read_data=False, 
                    debugger=self.dbg,
                    use_cache=True
                )

                if p.address == self.ptm.top(self.cache.mstate):
                    avail += self.ptm.chunksize(p)
                    break

                if p.type == pt.chunk_type.FREE_FAST:
                    avail += self.ptm.chunksize(p)
                elif p.type == pt.chunk_type.FREE_TCACHE:
                    avail += self.ptm.chunksize(p)
                elif p.type == pt.chunk_type.INUSE:
                    inuse += self.ptm.chunksize(p)
                else:
                    avail += self.ptm.chunksize(p)
                nblocks += 1

                addr = self.ptm.next_chunk(p)

            pu.print_header("Arena {} @ {:#x}:".format(arena, mstate.address), end="\n")
            print("{:16} = ".format("system bytes"), end="")
            pu.print_value("{} ({:#x})".format(mstate.max_system_mem, mstate.max_system_mem), end="\n")
            print("{:16} = ".format("free bytes"), end="")
            pu.print_value("{} ({:#x})".format(avail, avail), end="\n")
            print("{:16} = ".format("in use bytes"), end="")
            pu.print_value("{} ({:#x})".format(inuse, inuse), end="\n")

            system_b += mstate.max_system_mem
            avail_b += avail
            in_use_b += inuse

            if mstate.next == main_arena_address:
                break
            else:
                next_addr = self.dbg.format_address(mstate.next)
                mstate = ms.malloc_state(
                    self.ptm, next_addr, debugger=self.dbg, version=self.version
                )
                arena += 1

        pu.print_header("\nTotal (including mmap):", end="\n")
        print("{:16} = ".format("system bytes"), end="")
        pu.print_value("{} ({:#x})".format(system_b, system_b), end="\n")
        print("{:16} = ".format("free bytes"), end="")
        pu.print_value("{} ({:#x})".format(avail_b, avail_b), end="\n")
        print("{:16} = ".format("in use bytes"), end="")
        pu.print_value("{} ({:#x})".format(in_use_b, in_use_b), end="\n")

        if self.version <= 2.23:
            # catch the error before we print anything
            val = par.max_total_mem

            print("{:16} = ".format("max system bytes"), end="")
            pu.print_value("{}".format(val), end="\n")

        print("{:16} = ".format("max mmap regions"), end="")
        pu.print_value("{}".format(par.max_n_mmaps), end="\n")
        print("{:16} = ".format("max mmap bytes"), end="")
        pu.print_value("{}".format(par.max_mmapped_mem), end="\n")
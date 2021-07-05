# -*- coding: future_fstrings -*-
from __future__ import print_function

import argparse
import sys
import logging

from libptmalloc.frontend import printutils as pu
from libptmalloc.ptmalloc import malloc_chunk as mc
from libptmalloc.ptmalloc import malloc_par as mp
from libptmalloc.ptmalloc import malloc_state as ms
from libptmalloc.ptmalloc import ptmalloc as pt
from libptmalloc.frontend import helpers as h
from libptmalloc.frontend.commands.gdb import ptchunk
from libptmalloc.frontend.commands.gdb import ptcmd

log = logging.getLogger("libptmalloc")
log.trace("ptlist.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")

class ptlist(ptcmd.ptcmd):
    """Command to print a flat listing of all the chunks in an arena
    
    Also see ptchunk description

    Inspired by jp's phrack print and arena.c"""

    def __init__(self, ptm):
        log.debug("ptlist.__init__()")
        super(ptlist, self).__init__(ptm, "ptlist")

        self.parser = argparse.ArgumentParser(
            description="""Print a flat listing of all the chunks in an arena""", 
            add_help=False, 
            formatter_class=argparse.RawTextHelpFormatter,
            epilog="""E.g.
ptlist -M "tag, backtrace:5" """)
        self.parser.add_argument(
            "address", default=None, nargs="?", type=h.string_to_int,
            help="A malloc_mstate struct address. Optional with cached mstate"
        )
        self.parser.add_argument(
            "-C", "--compact", dest="compact", action="store_true", default=False,
            help="Compact flat heap listing"
        )
        # "ptchunk" also has this argument but default for 
        # "ptlist" is to show unlimited number of chunks
        self.parser.add_argument(
            "-c", "--count", dest="count", type=h.check_positive, default=None,
            help="Number of chunks to print linearly"
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

        log.debug("ptlist.invoke()")

        self.cache.update_all(show_status=self.args.debug, use_cache=self.args.use_cache, arena_address=self.args.address)

        log.debug("ptlist.invoke() (2)")

        mstate = self.cache.mstate
        par = self.cache.par

        if mstate.address == self.cache.main_arena_address:
            start, _ = self.dbg.get_heap_address(par)
        else:
            print("Using manual arena calculation for heap start")
            start = (mstate.address + mstate.size + self.ptm.MALLOC_ALIGN_MASK) & ~self.ptm.MALLOC_ALIGN_MASK
        self.sbrk_base = start

        if self.args.compact:
            self.compact_listing()
        else:
            self.listing()

    def listing(self):
        """Print all the chunks in all the given arenas using a flat listing
        """

        pu.print_title("{:>15} for arena @ {:#x}".format("flat heap listing", self.cache.mstate.address), end="\n")

        # Prepare arguments for "ptchunk" format
        # i.e. there is only one start address == sbrk_base
        if self.ptm.SIZE_SZ == 4:
            # Workaround on 32-bit. Empirically it seems the first chunk starts at offset +0x8?
            self.args.addresses = [ f"{self.sbrk_base+0x8:#x}"]
        else:
            self.args.addresses = [ f"{self.sbrk_base:#x}"]
        self.args.no_newline = False
        
        chunks = ptchunk.ptchunk.parse_many2(self)

        if len(chunks) > 0:
            if self.args.count == None:
                print(f"Total of {len(chunks)} chunks")
            else:
                print(f"Total of {len(chunks)}+ chunks")

        if self.args.json_filename != None:
            ptchunk.ptchunk.dump_json(self, chunks)

    def compact_listing(self):
        """Print all the chunks in a given arena using a compact flat listing
        """

        max_count = self.args.count

        pu.print_title("{:>15} for arena @ {:#x}".format("compact flat heap listing", self.cache.mstate.address), end="\n")

        if self.ptm.SIZE_SZ == 4:
            # Workaround on 32-bit. Empirically it seems the first chunk starts at offset +0x8?
            addr = self.sbrk_base+8
        else:
            addr = self.sbrk_base

        count = 0
        while True:
            p = mc.malloc_chunk(
                self.ptm, 
                addr, 
                read_data=False, 
                debugger=self.dbg,
                use_cache=True
            )

            if p.address == self.ptm.top(self.cache.mstate):
                print("|T", end="")
                count += 1
                break

            if p.type == pt.chunk_type.FREE_FAST:
                print("|f%d" % self.ptm.fast_bin_index(self.ptm.chunksize(p)), end="")
            elif p.type == pt.chunk_type.FREE_TCACHE:
                print("|t%d" % self.ptm.tcache_bin_index(self.ptm.chunksize(p)), end="")
            elif p.type == pt.chunk_type.INUSE:
                print("|M", end="")
            else:
                if (
                    (p.fd == self.cache.mstate.last_remainder)
                    and (p.bk == self.cache.mstate.last_remainder)
                    and (self.cache.mstate.last_remainder != 0)
                ):
                    print("|L", end="")
                else:
                    print("|F%d" % self.ptm.bin_index(self.ptm.chunksize(p)), end="")
            count += 1
            sys.stdout.flush()

            if max_count != None and count == max_count:
                break

            addr = self.ptm.next_chunk(p)

        print("|")
        if max_count == None:
            print(f"Total of {count} chunks")
        else:
            print(f"Total of {count}+ chunks")
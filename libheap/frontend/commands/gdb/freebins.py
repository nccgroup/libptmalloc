from __future__ import print_function

import sys

from libheap.frontend.printutils import print_error, print_header, print_value
from libheap.ptmalloc.malloc_chunk import malloc_chunk
from libheap.ptmalloc.malloc_state import malloc_state
from libheap.ptmalloc.ptmalloc import ptmalloc

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    sys.exit()


class freebins(gdb.Command):
    """Walk and print the nonempty free bins."""

    def __init__(self, debugger=None, version=None):
        super(freebins, self).__init__(
            "freebins", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE
        )

        if debugger is not None:
            self.dbg = debugger
        else:
            print_error("Please specify a debugger")
            sys.exit()

        self.version = version

    def invoke(self, arg, from_tty):
        "modified from jp's phrack printing"

        ptm = ptmalloc(debugger=self.dbg)

        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

        arena_address = self.dbg.read_variable_address("main_arena")
        ar_ptr = malloc_state(arena_address, debugger=self.dbg, version=self.version)
        # XXX: fixme for glibc <= 2.19 with THREAD_STATS
        fb_base = int(ar_ptr.address) + ar_ptr.fastbins_offset
        # mchunkptr bins in struct malloc_state
        sb_base = int(ar_ptr.address) + ar_ptr.bins_offset

        # print_title("Heap Dump")

        for fb in range(0, ptm.NFASTBINS):
            print_once = True
            p = malloc_chunk(
                fb_base - (2 * ptm.SIZE_SZ) + fb * ptm.SIZE_SZ,
                inuse=False,
                debugger=self.dbg,
            )

            while p.fd != 0:
                if p.fd is None:
                    break

                if print_once:
                    print_once = False
                    if fb > 0:
                        print("")
                    print_header("fast bin {}".format(fb), end="")
                    print(" @ ", end="")
                    print_value("{:#x}".format(p.fd), end="")

                print("\n\tfree chunk @ ", end="")
                print_value("{:#x} ".format(int(p.fd)))
                print("- size ", end="")
                p = malloc_chunk(p.fd, inuse=False, debugger=self.dbg)
                print("{:#x}".format(int(ptm.chunksize(p))), end="")

        for i in range(1, ptm.NBINS):
            print_once = True

            b = sb_base + i * 2 * ptm.SIZE_SZ - 4 * ptm.SIZE_SZ
            first = ptm.first(malloc_chunk(b, inuse=False, debugger=self.dbg))
            p = malloc_chunk(first, inuse=False, debugger=self.dbg)

            while p.address != int(b):
                if print_once:
                    print("")
                    print_once = False

                    if i == 1:
                        print_header("unsorted bin", end="")
                    else:
                        print_header("small bin {}".format(i))

                    print(" @ ", end="")
                    print_value("{:#x}".format(int(b) + 2 * ptm.SIZE_SZ), end="")

                print("\n\tfree chunk @ ", end="")
                print_value("{:#x} ".format(int(p.address)))
                print("- size ", end="")
                print("{:#x}".format(int(ptm.chunksize(p))), end="")
                p = malloc_chunk(ptm.first(p), inuse=False, debugger=self.dbg)

        print("")

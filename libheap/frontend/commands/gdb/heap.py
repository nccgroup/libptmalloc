from __future__ import print_function

import sys

from libheap.frontend.printutils import print_error, print_header
from libheap.ptmalloc.malloc_state import malloc_state
from libheap.ptmalloc.ptmalloc import ptmalloc

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception('sys.exit()')


class heap(gdb.Command):
    """libheap command help listing"""

    def __init__(self, debugger=None, version=None):
        super(heap, self).__init__("heap", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

        if debugger is not None:
            self.dbg = debugger
        else:
            print_error("Please specify a debugger")
            raise Exception('sys.exit()')

        self.version = version

    def invoke(self, arg, from_tty):
        # XXX: self.dbg.string_to_argv
        if arg.find("-h") != -1:
            print_header("{:<20}".format("heap [-a 0x1234]"), end="")
            print("Print main_arena or arena at specified address")
            print_header("{:<20}".format("heapls"))
            print("Print a flat listing of all chunks in an arena")
            print_header("{:<20}".format("fastbins [#]"))
            print("Print all fast bins, or only a single fast bin")
            print_header("{:<20}".format("smallbins [#]"))
            print("Print all small bins, or only a single small bin")
            print_header("{:<20}".format("freebins"))
            print("Print compact bin listing (only free chunks)")
            print_header("{:<20}".format("heaplsc"))
            print("Print compact arena listing (all chunks)")
            print_header("{:<20}".format("mstats"), end="")
            print("Print memory alloc statistics similar to malloc_stats(3)")
            # print_header("{:<22}".format("print_bin_layout [#]"), end="")
            # print("Print the layout of a particular free bin")
            print("Currently configured for version: {}".format(self.version))
            return

        ptm = ptmalloc(self.dbg)

        if ptm.SIZE_SZ == 0:
            ptm.set_globals()

        arena_address = self.dbg.read_variable_address("main_arena")
        if arena_address is None:
            print_error("main_arena address could not be found")
            return
        ar_ptr = malloc_state(arena_address, debugger=self.dbg, version=self.version)

        # XXX: add arena address passing via arg (-a)
        if (len(arg) == 0) and (ar_ptr.next == 0):
            # struct malloc_state may be invalid size (wrong glibc version)
            print_error("No arenas could be found at {:#x}".format(ar_ptr.address))
            return

        print("Arena(s) found:", end="\n")
        print("  arena @ ", end="")
        print_header("{:#x}".format(int(ar_ptr.address)), end="\n")

        if ar_ptr.address != ar_ptr.next:
            # we have more than one arena

            curr_arena = malloc_state(
                ar_ptr.next, debugger=self.dbg, version=self.version
            )

            while ar_ptr.address != curr_arena.address:
                print("  arena @ ", end="")
                print_header("{:#x}".format(int(curr_arena.address)), end="\n")
                curr_arena = malloc_state(
                    curr_arena.next, debugger=self.dbg, version=self.version
                )

                if curr_arena.address == 0:
                    print_error("No arenas could be correctly found.")
                    break  # breaking infinite loop

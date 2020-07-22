from __future__ import print_function

import struct
import sys

from libheap.frontend.printutils import print_error, print_title, print_value
from libheap.ptmalloc.malloc_chunk import malloc_chunk
from libheap.ptmalloc.malloc_state import malloc_state
from libheap.ptmalloc.ptmalloc import ptmalloc

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")


class smallbins(gdb.Command):
    """Walk and print the small bins."""

    def __init__(self, ptm, debugger=None, version=None):
        super(smallbins, self).__init__(
            "smallbins", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE
        )

        self.ptm = ptm
        if debugger is not None:
            self.dbg = debugger
        else:
            print_error("Please specify a debugger")
            raise Exception("sys.exit()")

        self.version = version

    def invoke(self, arg, from_tty):
        if not self.ptm:
            self.ptm = ptmalloc(debugger=self.dbg)

        if self.ptm.SIZE_SZ == 0:
            self.ptm.set_globals()

        # XXX figure out where these pads come from
        if self.ptm.SIZE_SZ == 4:
            pad_width = 27
        elif self.ptm.SIZE_SZ == 8:
            pad_width = 31

        main_arena_address = self.dbg.read_variable_address("main_arena")
        arena_address = self.dbg.format_address(main_arena_address)
        ar_ptr = malloc_state(arena_address, debugger=self.dbg, version=self.version)

        # mchunkptr bins in struct malloc_state
        sb_base = int(ar_ptr.address) + ar_ptr.bins_offset

        if len(arg) == 0:
            sb_num = None
        else:
            sb_num = int(arg.split(" ")[0])

            if (sb_num * 2) > self.ptm.NBINS:
                print_error("Invalid smallbin number")
                return

        print_title("smallbins", end="")

        for sb in range(2, self.ptm.NBINS + 2, 2):
            if sb_num is not None and sb_num != 0:
                sb = sb_num * 2

            offset = sb_base + (sb - 2) * self.ptm.SIZE_SZ
            try:
                mem = self.dbg.read_memory(offset, 2 * self.ptm.SIZE_SZ)
                if self.ptm.SIZE_SZ == 4:
                    fd, bk = struct.unpack("<II", mem)
                elif self.ptm.SIZE_SZ == 8:
                    fd, bk = struct.unpack("<QQ", mem)
            except RuntimeError:
                print_error("Invalid smallbin addr {0:#x}".format(offset))
                return

            print("")
            smallbin_index = int(sb / 2)
            if smallbin_index == 0:
                print("[ unsorted ] ", end="")
            else:
                print("[    sb {:02} ] ".format(smallbin_index), end="")
            print("{:#x}{:>{width}}".format(int(offset), "-> ", width=5), end="")
            if fd == (offset - 2 * self.ptm.SIZE_SZ):
                print("[ {:#x} | {:#x} ] ".format(int(fd), int(bk)), end="")
            else:
                print_value("[ {:#x} | {:#x} ] ".format(int(fd), int(bk)))

            while 1:
                if fd == (offset - 2 * self.ptm.SIZE_SZ):
                    break

                chunk = malloc_chunk(self.ptm, addr=fd, inuse=False, debugger=self.dbg)
                print("")
                print_value(
                    "{:>{width}}{:#x} | {:#x} ] ".format(
                        "[ ", int(chunk.fd), int(chunk.bk), width=pad_width
                    )
                )
                chunk_size = int(self.ptm.chunksize(chunk))
                print("({})".format(hex(chunk_size)), end="")
                fd = chunk.fd

            if sb_num is not None:  # only print one smallbin
                break

        print("")

import struct
import sys

from libheap import ptmalloc
from libheap.frontend.printutils import color_title, color_value, print_error
from libheap.ptmalloc.heap_structure import heap_structure


class malloc_chunk(heap_structure):
    """python representation of a struct malloc_chunk

        allow_invalid: sometimes these structures will be used for
        that isn't actually a complete chunk, like a freebin, in these cases we
        still wanted to be able to parse so that we can access the forward and
        backward pointers, so shouldn't complain about their being invalid size
    """

    def __init__(
        self,
        ptm,
        addr=None,
        mem=None,
        size=None,
        inuse=None,
        read_data=True,
        debugger=None,
        allow_invalid=False,
    ):
        super(malloc_chunk, self).__init__(ptm, debugger=debugger)
        if not self.initOK:
            return

        self.prev_size = 0
        self.size = 0
        self.data = None
        # free specific
        self.fd = None
        self.bk = None

        # large blocks specific + free specific
        self.fd_nextsize = None
        self.bk_nextsize = None

        # actual chunk flags
        self.cinuse_bit = 0

        # fast chunk do not have their cinuse bit set when they are free
        # instead we keep the info here
        self.fastchunk_freed = False

        # general indicator if we are inuse
        self.inuse = inuse

        self.data_address = None
        self.hdr_size = 0

        self.mem = mem
        self.from_mem = False
        self.is_top = False

        if not self.validate_address(addr):
            return

        if debugger is not None:
            self.debugger = debugger
        elif mem is None:
            print_error("no active debugger and no memory specified")
            return

        self.SIZE_SZ = self.ptm.SIZE_SZ

        if mem is None:
            # a string of raw memory was not provided
            try:
                mem = self.debugger.read_memory(addr, self.ptm.INUSE_HDR_SZ)
            except TypeError:
                print_error("Invalid address specified.")
                return None
            except RuntimeError:
                print_error("Could not read address {0:#x}".format(addr))
                return None
        else:
            self.from_mem = True
            # a string of raw memory was provided
            if self.inuse:
                if len(mem) < self.ptm.INUSE_HDR_SZ:
                    print_error("Insufficient mem provided for malloc_chunk.")
                    self.initOK = False
                    return None
                # header only provided
                elif len(mem) == self.ptm.INUSE_HDR_SZ:
                    read_data = False
            elif len(mem) < self.ptm.FREE_HDR_SZ:
                print_error("Insufficient memory provided for a free chunk.")
                self.initOK = False
                return None

        if self.SIZE_SZ == 4:
            (self.prev_size, self.size) = struct.unpack_from("<II", mem, 0x0)
        elif self.SIZE_SZ == 8:
            (self.prev_size, self.size) = struct.unpack_from("<QQ", mem, 0x0)

        if not allow_invalid and self.size == 0:
            print_error("chunk with zero size detected at 0x%x" % self.address)
            self.initOK = False
            return

        # XXX - add support for seeing if mem has enough space
        # XXX - check of the computed address goes outside of the arena
        # boundary instead of just accepting some bad chunk
        if self.size != 0 and self.debugger:
            # read next chunk size field to determine if current chunk is inuse
            if size is None:
                nextchunk_addr = self.address + (self.size & ~self.ptm.SIZE_BITS)
            else:
                nextchunk_addr = self.address + (size & ~self.ptm.SIZE_BITS)

            if self.ptm.ar_ptr and self.address == self.ptm.ar_ptr.top:
                self.cinuse_bit = 0
                self.is_top = True
            else:
                nextchunk_error = False
                try:
                    mem2 = self.debugger.read_memory(
                        nextchunk_addr + self.ptm.SIZE_SZ, self.ptm.SIZE_SZ
                    )
                # except gdb.MemoryError:
                except Exception:
                    if not allow_invalid:
                        print("self.address: 0x%x" % self.address)
                        print_error(
                            "Could not read nextchunk (@0x%x) size. Invalid chunk address?" % nextchunk_addr
                        )
                        self.initOK = False
                        return
                    nextchunk_error = True
                if not nextchunk_error:
                    if self.ptm.SIZE_SZ == 4:
                        nextchunk_size = struct.unpack_from("<I", mem2, 0x0)[0]
                    elif self.ptm.SIZE_SZ == 8:
                        nextchunk_size = struct.unpack_from("<Q", mem2, 0x0)[0]
                    self.cinuse_bit = nextchunk_size & self.ptm.PREV_INUSE

        # XXX - add check to see if we are inuse, but a fastbin
        # One option is to walk the associated fastbin entry if it would fit in
        # one, but this is hella slow over serial.
        # if self.cinuse_bit:
        #    mem = self.inferior.read_memory(addr + 2 * self.ptm.SIZE_SZ, 4)
        #    next_word = struct.unpack_from("<I", mem, 0x0)[0]
        #    if next_word != 0xA11C0123:
        #        self.fastchunk_freed = True

        # decide if chunk is actually inuse
        if inuse is None:
            if self.cinuse_bit and not self.fastchunk_freed:
                self.inuse = True
            else:
                self.inuse = False
        else:
            # Trust the caller is right
            self.inuse = inuse

        # now that we know the size and if it is inuse/freed, we can determine
        # the chunk type and though the chunk header size
        if self.inuse is True:
            self.hdr_size = self.ptm.INUSE_HDR_SZ
        else:
            if size is None:
                if self.fastchunk_freed:
                    self.hdr_size = self.ptm.FREE_FASTCHUNK_HDR_SZ
                elif self.ptm.in_smallbin_range(self.size):
                    self.hdr_size = self.ptm.FREE_HDR_SZ
                else:
                    self.hdr_size = self.ptm.FREE_LARGE_HDR_SZ
            else:
                # Trust the caller size
                if self.ptm.in_smallbin_range(size):
                    self.hdr_size = self.ptm.FREE_HDR_SZ
                else:
                    self.hdr_size = self.ptm.FREE_LARGE_HDR_SZ

        # parse additional fields in chunk header depending on type
        # fastbins freed follows
        if self.hdr_size == self.ptm.FREE_FASTCHUNK_HDR_SZ:
            if self.address is not None:
                # a string of raw memory was not provided
                if self.debugger is not None:
                    if self.ptm.SIZE_SZ == 4:
                        mem = self.debugger.read_memory(
                            self.address, self.ptm.FREE_FASTCHUNK_HDR_SZ
                        )
                    elif self.ptm.SIZE_SZ == 8:
                        mem = self.debugger.read_memory(
                            self.address, self.ptm.FREE_FASTCHUNK_HDR_SZ
                        )
            if self.ptm.SIZE_SZ == 4:
                self.fd = struct.unpack_from("<I", mem, self.ptm.INUSE_HDR_SZ)[0]
            elif self.ptm.SIZE_SZ == 8:
                self.fd = struct.unpack_from("<Q", mem, self.ptm.INUSE_HDR_SZ)[0]
        # smallbin freed follows
        elif self.hdr_size == self.ptm.FREE_HDR_SZ:
            if self.address is not None:
                # a string of raw memory was not provided
                if self.debugger is not None:
                    if self.ptm.SIZE_SZ == 4:
                        mem = self.debugger.read_memory(
                            self.address, self.ptm.FREE_HDR_SZ
                        )
                    elif self.ptm.SIZE_SZ == 8:
                        mem = self.debugger.read_memory(
                            self.address, self.ptm.FREE_HDR_SZ
                        )
            if self.ptm.SIZE_SZ == 4:
                (self.fd, self.bk) = struct.unpack_from(
                    "<II", mem, self.ptm.INUSE_HDR_SZ
                )
            elif self.ptm.SIZE_SZ == 8:
                (self.fd, self.bk) = struct.unpack_from(
                    "<QQ", mem, self.ptm.INUSE_HDR_SZ
                )
        # largebin freed freed follows
        elif self.hdr_size == self.ptm.FREE_LARGE_HDR_SZ:
            if self.address is not None:
                # a string of raw memory was not provided
                if self.debugger is not None:
                    if self.ptm.SIZE_SZ == 4:
                        mem = self.debugger.read_memory(
                            self.address, self.ptm.FREE_LARGE_HDR_SZ
                        )
                    elif self.ptm.SIZE_SZ == 8:
                        mem = self.debugger.read_memory(
                            self.address, self.ptm.FREE_LARGE_HDR_SZ
                        )
            if self.ptm.SIZE_SZ == 4:
                (
                    self.fd,
                    self.bk,
                    self.fd_nextsize,
                    self.bk_nextsize,
                ) = struct.unpack_from("<IIII", mem, self.ptm.INUSE_HDR_SZ)
            elif self.ptm.SIZE_SZ == 8:
                (
                    self.fd,
                    self.bk,
                    self.fd_nextsize,
                    self.bk_nextsize,
                ) = struct.unpack_from("<QQQQ", mem, self.ptm.INUSE_HDR_SZ)

        # keep track where the data follows
        if self.address is not None:
            self.data_address = self.address + self.hdr_size

    def write(self, inferior=None):
        if self.fd is None and self.bk is None:
            inuse = True
        else:
            inuse = False

        if inuse:
            if self.SIZE_SZ == 4:
                mem = struct.pack("<II", self.prev_size, self.size)
                if self.data is not None:
                    mem += struct.pack("<%dI" % len(self.data), *self.data)
            elif self.SIZE_SZ == 8:
                mem = struct.pack("<QQ", self.prev_size, self.size)
                if self.data is not None:
                    mem += struct.pack("<%dQ" % len(self.data), *self.data)
        else:
            if self.SIZE_SZ == 4:
                mem = struct.pack(
                    "<IIIIII",
                    self.prev_size,
                    self.size,
                    self.fd,
                    self.bk,
                    self.fd_nextsize,
                    self.bk_nextsize,
                )
            elif self.SIZE_SZ == 8:
                mem = struct.pack(
                    "<QQQQQQ",
                    self.prev_size,
                    self.size,
                    self.fd,
                    self.bk,
                    self.fd_nextsize,
                    self.bk_nextsize,
                )

        if self.debugger is not None:
            self.debugger.write_memory(self.address, mem)
        elif inferior is not None:
            inferior.write_memory(self.address, mem)

    def __str__(self):
        # XXX - missing colors due to port
        if self.prev_size == 0 and self.size == 0:
            return ""
        # XXX - since they all share the same prev_size/size and 2 chunk types
        # also share the fd/bk, we could refactor code here?
        elif self.hdr_size == self.ptm.INUSE_HDR_SZ:
            ret = "struct malloc_chunk @ "
            ret += "{:#x} ".format(self.address)
            ret += "{"
            ret += "\n{:11} = ".format("prev_size")
            ret += "{:#x}".format(self.prev_size)
            ret += "\n{:11} = ".format("size")
            ret += "{:#x}".format(self.size & ~self.ptm.SIZE_BITS)

            if (
                self.ptm.prev_inuse(self)
                or self.ptm.chunk_is_mmapped(self)
                or self.ptm.chunk_non_main_arena(self)
            ):
                ret += " ("
                if self.ptm.prev_inuse(self):
                    ret += "PREV_INUSE|"
                if self.ptm.chunk_is_mmapped(self):
                    ret += "MMAPPED|"
                if self.ptm.chunk_non_main_arena(self):
                    ret += "NON_MAIN_ARENA|"
                ret += "\b)"
            return ret
        elif self.hdr_size == self.ptm.FREE_FASTCHUNK_HDR_SZ:
            ret = "struct malloc_chunk @ "
            ret += "{:#x} ".format(self.address)
            ret += "{"
            ret += "\n{:11} = ".format("prev_size")
            ret += "{:#x}".format(self.prev_size)
            ret += "\n{:11} = ".format("size")
            ret += "{:#x}".format(self.size & ~self.ptm.SIZE_BITS)
            flag_str = ""
            if self.ptm.prev_inuse(self):
                flag_str += "PREV_INUSE|"
            if self.ptm.chunk_is_mmapped(self):
                flag_str += "MMAPPED|"
            if self.ptm.chunk_non_main_arena(self):
                flag_str += "NON_MAIN_ARENA|"
            if len(flag_str) != 0:
                ret += " ("
                ret += flag_str
                ret += "\b)"
            ret += "\n{:11} = ".format("fd")
            ret += "{:#x}".format(self.fd)
            return ret
        elif self.hdr_size == self.ptm.FREE_HDR_SZ:
            ret = "struct malloc_chunk @ "
            ret += "{:#x} ".format(self.address)
            ret += "{"
            ret += "\n{:11} = ".format("prev_size")
            ret += "{:#x}".format(self.prev_size)
            ret += "\n{:11} = ".format("size")
            ret += "{:#x}".format(self.size & ~self.ptm.SIZE_BITS)
            ret += " ("
            if self.ptm.prev_inuse(self):
                ret += "PREV_INUSE|"
            if self.ptm.chunk_is_mmapped(self):
                ret += "MMAPPED|"
            if self.ptm.chunk_non_main_arena(self):
                ret += "NON_MAIN_ARENA|"
            ret += "\b)"
            ret += "\n{:11} = ".format("fd")
            ret += "{:#x}".format(self.fd)
            ret += "\n{:11} = ".format("bk")
            ret += "{:#x}".format(self.bk)
            return ret
        elif self.hdr_size == self.ptm.FREE_LARGE_HDR_SZ:
            ret = color_title("struct malloc_chunk @ ")
            ret += "{:#x} ".format(self.address)
            ret += "{"
            ret += "\n{:11} = ".format("prev_size")
            ret += "{:#x}".format(self.prev_size)
            ret += "\n{:11} = ".format("size")
            ret += "{:#x}".format(self.size & ~self.ptm.SIZE_BITS)
            ret += " ("
            if self.ptm.prev_inuse(self):
                ret += "PREV_INUSE|"
            if self.ptm.chunk_is_mmapped(self):
                ret += "MMAPPED|"
            if self.ptm.chunk_non_main_arena(self):
                ret += "NON_MAIN_ARENA|"
            ret += "\b)"
            ret += "\n{:11} = ".format("fd")
            ret += "{:#x}".format(self.fd)
            ret += "\n{:11} = ".format("bk")
            ret += "{:#x}".format(self.bk)
            ret += "\n{:11} = ".format("fd_nextsize")
            ret += "{:#x}".format(self.fd_nextsize)
            ret += "\n{:11} = ".format("bk_nextsize")
            ret += "{:#x}".format(self.bk_nextsize)
            return ret
        else:
            self.ptm.logmsg("Error: unknown hdr_size. Should not happen")
            return ""

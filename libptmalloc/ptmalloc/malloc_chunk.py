# -*- coding: future_fstrings -*-
import struct
import sys
import logging

log = logging.getLogger("libptmalloc")
log.trace(f"malloc_chunk.py")

from libptmalloc.frontend import printutils as pu
from libptmalloc.ptmalloc import heap_structure as hs
from libptmalloc.frontend import helpers as h
from libptmalloc.frontend.commands.gdb import pttcache
from libptmalloc.frontend.commands.gdb import ptfast
from libptmalloc.ptmalloc import ptmalloc as pt

class malloc_chunk(hs.heap_structure):
    """python representation of a struct malloc_chunk

    This is the main structure representing a chunk.
    """

    # XXX - probably ptm can just have the debugger
    def __init__(
        self,
        ptm,
        addr=None,
        mem=None,
        size=None,
        inuse=None,
        tcache=None,
        fast=None,
        read_data=True, # XXX - actually use that argument
        debugger=None,
        allow_invalid=False,
        use_cache=False,
    ):
        """
        Parse chunk's data and initialize the malloc_chunk object

        :param ptm: ptmalloc object
        :param addr: chunk address where to read the chunk's content from the debugger
        :param mem: alternatively to "addr", provides the memory bytes of that chunk's content
        :param size: provide the chunk's size if you know it (not required)
        :param inuse: True if we know it is an inuse chunk (i.e. not in any bin) (not required)
        :param tcache: True if we know it is a chunk in the tcache bins,
                        False if we know it is NOT in the tcache bins. 
                        None otherwise.
                        Whenever possible, specify it as otherwise it will try
                        to search for it in the tcache array which is slower
        :param fast: Same as "tcache" but for fast bins
        :param read_data: XXX
        :param debugger: the pydbg object
        :param allow_invalid: sometimes these structures will be used for
                              that isn't actually a complete chunk, like a freebin, in these cases we
                              still wanted to be able to parse so that we can access the forward and
                              backward pointers, so shouldn't complain about their being invalid size
        :param use_cache: True if we want to use the cached information from the cache object.
                          False if we want to fetch the data again
        """

        super(malloc_chunk, self).__init__(ptm, debugger=debugger)
        if not self.initOK:
            return

        if fast is True and tcache is True:
            raise Exception("Can't be fast and tcache at the same time")

        if fast is True:
            tcache = False

        if tcache is True:
            fast = False

        self.prev_size = 0
        self.size = 0
        self.data = None

        # tcache specific
        # Note: In glibc source, it is part of another structure (tcache_entry) but is simpler
        # to just have it tracked in the malloc_chunk object
        self.next = None
        self.key = None

        # free specific
        self.fd = None
        self.bk = None

        # large blocks specific + free specific
        self.fd_nextsize = None
        self.bk_nextsize = None

        # actual chunk flags
        self.cinuse_bit = 0

        # general indicator if we are inuse
        # XXX - is redondant with self.type so need to get rid of it
        self.inuse = inuse

        self.data_address = None
        self.hdr_size = 0

        self.mem = mem
        self.from_mem = False
        self.is_top = False
        self.type = None    # ptmalloc.chunk_type

        cache = self.ptm.cache

        if not self.validate_address(addr):
            return
        log.info("malloc_chunk(): self.address = 0x%x" % self.address)

        if self.dbg is None and mem is None:
            pu.print_error("no active debugger and no memory specified")
            return

        self.SIZE_SZ = self.ptm.SIZE_SZ

        if mem is None:
            # a string of raw memory was not provided
            try:
                mem = self.dbg.read_memory(addr, self.ptm.INUSE_HDR_SZ)
            except TypeError:
                pu.print_error("Invalid address specified")
                self.initOK = False
                return
            except RuntimeError:
                pu.print_error("Could not read address {0:#x}".format(addr))
                self.initOK = False
                return
        else:
            self.from_mem = True
            # a string of raw memory was provided
            if self.inuse:
                if len(mem) < self.ptm.INUSE_HDR_SZ:
                    pu.print_error("Insufficient mem provided for malloc_chunk.")
                    self.initOK = False
                    return
                # header only provided
                elif len(mem) == self.ptm.INUSE_HDR_SZ:
                    read_data = False
            elif len(mem) < self.ptm.FREE_HDR_SZ:
                pu.print_error("Insufficient memory provided for a free chunk.")
                self.initOK = False
                return

        if self.SIZE_SZ == 4:
            (self.prev_size, self.size) = struct.unpack_from("<II", mem, 0x0)
        elif self.SIZE_SZ == 8:
            (self.prev_size, self.size) = struct.unpack_from("<QQ", mem, 0x0)

        if not allow_invalid and self.size == 0:
            pu.print_error("chunk with zero size detected at 0x%x" % self.address)
            self.initOK = False
            return

        # XXX - add support for seeing if mem has enough space

        # XXX - check of the computed address goes outside of the arena
        # boundary instead of just accepting some bad chunk

        if self.size != 0 and self.dbg:
            # read next chunk size field to determine if current chunk is inuse
            if size is None:
                nextchunk_addr = self.address + (self.size & ~self.ptm.SIZE_BITS)
            else:
                nextchunk_addr = self.address + (size & ~self.ptm.SIZE_BITS)

            if cache.mstate and self.address == self.ptm.top(cache.mstate):
                self.cinuse_bit = 0
                self.is_top = True
            else:
                nextchunk_error = False
                try:
                    mem2 = self.dbg.read_memory(
                        nextchunk_addr + self.ptm.SIZE_SZ, self.ptm.SIZE_SZ
                    )
                # except gdb.MemoryError:
                except Exception:
                    if not allow_invalid:
                        #print("self.address: 0x%x" % self.address)
                        pu.print_error(
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

        if fast is None:
            # XXX - if too slow, we could specify the bin size?
            fast = ptfast.ptfast.is_in_fastbin(self.address, self.ptm, dbg=self.dbg, use_cache=use_cache)
        else:
            # Trust the caller is right
            pass
        log.debug(f"fast = {str(fast)}")

        if tcache is None:
            # XXX - if too slow, we could specify the bin size?
            tcache = pttcache.pttcache.is_in_tcache(self.address, self.ptm, dbg=self.dbg, use_cache=use_cache)
        else:
            # Trust the caller is right
            pass
        log.debug(f"tcache = {str(tcache)}")

        # decide if chunk is actually inuse
        if inuse is None:
            if self.cinuse_bit and not fast and not tcache:
                self.inuse = True
            else:
                self.inuse = False
        else:
            # Trust the caller is right
            self.inuse = inuse

        # now that we know the size and if it is inuse/freed, we can determine
        # the chunk type and though the chunk header size
        if self.inuse is True:
            self.type = pt.chunk_type.INUSE
        else:
            if size is None:
                if fast is True:
                    self.type = pt.chunk_type.FREE_FAST
                elif tcache is True:
                    self.type = pt.chunk_type.FREE_TCACHE
                elif self.ptm.in_smallbin_range(self.size):
                    self.type = pt.chunk_type.FREE_SMALL
                else:
                    self.type = pt.chunk_type.FREE_LARGE
            else:
                # Trust the caller size
                if self.ptm.in_smallbin_range(size):
                    self.type = pt.chunk_type.FREE_SMALL
                else:
                    self.type = pt.chunk_type.FREE_LARGE
        log.debug(f"self.hdr_size = {self.hdr_size:#x}")

        # parse additional fields in chunk header depending on type
        # fastbins freed follows
        if self.type == pt.chunk_type.INUSE:
            self.hdr_size = self.ptm.INUSE_HDR_SZ
        elif self.type == pt.chunk_type.FREE_FAST:
            self.hdr_size = self.ptm.FREE_FASTCHUNK_HDR_SZ
            if self.address is not None:
                # a string of raw memory was not provided
                if self.dbg is not None:
                    if self.ptm.SIZE_SZ == 4:
                        mem = self.dbg.read_memory(
                            self.address, self.ptm.FREE_FASTCHUNK_HDR_SZ
                        )
                    elif self.ptm.SIZE_SZ == 8:
                        mem = self.dbg.read_memory(
                            self.address, self.ptm.FREE_FASTCHUNK_HDR_SZ
                        )
            if self.ptm.SIZE_SZ == 4:
                self.fd = struct.unpack_from("<I", mem, self.ptm.INUSE_HDR_SZ)[0]
            elif self.ptm.SIZE_SZ == 8:
                self.fd = struct.unpack_from("<Q", mem, self.ptm.INUSE_HDR_SZ)[0]
        # tcache follows
        elif self.type == pt.chunk_type.FREE_TCACHE:
            self.hdr_size = self.ptm.FREE_TCACHE_HDR_SZ
            if self.address is not None:
                # a string of raw memory was not provided
                if self.dbg is not None:
                    if self.ptm.SIZE_SZ == 4:
                        mem = self.dbg.read_memory(
                            self.address, self.ptm.FREE_TCACHE_HDR_SZ
                        )
                    elif self.ptm.SIZE_SZ == 8:
                        mem = self.dbg.read_memory(
                            self.address, self.ptm.FREE_TCACHE_HDR_SZ
                        )
            if self.ptm.SIZE_SZ == 4:
                (self.next, self.key) = struct.unpack_from(
                    "<II", mem, self.ptm.INUSE_HDR_SZ
                )
            elif self.ptm.SIZE_SZ == 8:
                (self.next, self.key) = struct.unpack_from(
                    "<QQ", mem, self.ptm.INUSE_HDR_SZ
                )
        # smallbin freed follows
        elif self.type == pt.chunk_type.FREE_SMALL:
            self.hdr_size = self.ptm.FREE_HDR_SZ
            if self.address is not None:
                # a string of raw memory was not provided
                if self.dbg is not None:
                    if self.ptm.SIZE_SZ == 4:
                        mem = self.dbg.read_memory(
                            self.address, self.ptm.FREE_HDR_SZ
                        )
                    elif self.ptm.SIZE_SZ == 8:
                        mem = self.dbg.read_memory(
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
        elif self.type == pt.chunk_type.FREE_LARGE:
            self.hdr_size = self.ptm.FREE_LARGE_HDR_SZ
            if self.address is not None:
                # a string of raw memory was not provided
                if self.dbg is not None:
                    if self.ptm.SIZE_SZ == 4:
                        mem = self.dbg.read_memory(
                            self.address, self.ptm.FREE_LARGE_HDR_SZ
                        )
                    elif self.ptm.SIZE_SZ == 8:
                        mem = self.dbg.read_memory(
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
            log.debug(f"self.data_address = {self.data_address:#x}")

    # XXX - this is probably broken as we haven't used it yet
    def write(self, inferior=None):
        """Write chunk's data into memory using debugger
        """

        if self.fd is None and self.bk is None:
            inuse = True
        else:
            inuse = False

        # XXX - support tcache chunk

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

        if self.dbg is not None:
            self.dbg.write_memory(self.address, mem)
        elif inferior is not None:
            inferior.write_memory(self.address, mem)

    def __str__(self):
        """Pretty printer for the malloc_chunk
        """

        if self.prev_size == 0 and self.size == 0:
            return ""
        # XXX - since they all share the same prev_size/size and 2 chunk types
        # also share the fd/bk, we could refactor code here?
        elif self.type == pt.chunk_type.INUSE:

            title = "struct malloc_chunk @ 0x%x {" % self.address
            ret = pu.color_title(title)
            ret += "\n{:11} = ".format("prev_size")
            ret += pu.color_value("{:#x}".format(self.prev_size))
            ret += "\n{:11} = ".format("size")
            ret += pu.color_value("{:#x}".format(self.size & ~self.ptm.SIZE_BITS))

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
        elif self.type == pt.chunk_type.FREE_TCACHE:
            title = "struct malloc_chunk @ 0x%x {" % self.address
            ret = pu.color_title(title)
            ret += "\n{:11} = ".format("prev_size")
            ret += pu.color_value("{:#x}".format(self.prev_size))
            ret += "\n{:11} = ".format("size")
            ret += pu.color_value("{:#x}".format(self.size & ~self.ptm.SIZE_BITS))
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
            title = "\nstruct tcache_entry @ 0x%x {" % (self.address + self.ptm.INUSE_HDR_SZ)
            ret += pu.color_title(title)
            ret += "\n{:11} = ".format("next")
            ret += pu.color_value("{:#x}".format(self.next))
            ret += "\n{:11} = ".format("key")
            ret += pu.color_value("{:#x}".format(self.key))
            return ret
        elif self.type == pt.chunk_type.FREE_FAST:
            title = "struct malloc_chunk @ 0x%x {" % self.address
            ret = pu.color_title(title)
            ret += "\n{:11} = ".format("prev_size")
            ret += pu.color_value("{:#x}".format(self.prev_size))
            ret += "\n{:11} = ".format("size")
            ret += pu.color_value("{:#x}".format(self.size & ~self.ptm.SIZE_BITS))
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
            ret += pu.color_value("{:#x}".format(self.fd))
            return ret
        elif self.type == pt.chunk_type.FREE_SMALL:
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
            ret += pu.color_value("{:#x}".format(self.fd))
            ret += "\n{:11} = ".format("bk")
            ret += pu.color_value("{:#x}".format(self.bk))
            return ret
        elif self.type == pt.chunk_type.FREE_LARGE:
            title = "struct malloc_chunk @ 0x%x {" % self.address
            ret = pu.color_title(title)
            ret += "\n{:11} = ".format("prev_size")
            ret += pu.color_value("{:#x}".format(self.prev_size))
            ret += "\n{:11} = ".format("size")
            ret += pu.color_value("{:#x}".format(self.size & ~self.ptm.SIZE_BITS))
            ret += " ("
            if self.ptm.prev_inuse(self):
                ret += "PREV_INUSE|"
            if self.ptm.chunk_is_mmapped(self):
                ret += "MMAPPED|"
            if self.ptm.chunk_non_main_arena(self):
                ret += "NON_MAIN_ARENA|"
            ret += "\b)"
            ret += "\n{:11} = ".format("fd")
            ret += pu.color_value("{:#x}".format(self.fd))
            ret += "\n{:11} = ".format("bk")
            ret += pu.color_value("{:#x}".format(self.bk))
            ret += "\n{:11} = ".format("fd_nextsize")
            ret += pu.color_value("{:#x}".format(self.fd_nextsize))
            ret += "\n{:11} = ".format("bk_nextsize")
            ret += pu.color_value("{:#x}".format(self.bk_nextsize))
            return ret
        else:
            pu.print_error("Error: unknown hdr_size. Should not happen")
            return ""

# -*- coding: future_fstrings -*-
import struct
import sys
import logging

from libptmalloc.frontend import printutils as pu
from libptmalloc.ptmalloc import heap_structure as hs

log = logging.getLogger("libptmalloc")
log.trace("malloc_par.py")

class malloc_par(hs.heap_structure):
    "python representation of a struct malloc_par"

    CHUNK_ALIGNMENT = 16

    # XXX - we can probably get the version directly from the ptm argument?
    def __init__(self, ptm, addr=None, mem=None, debugger=None, version=None, invalid_ok=False):
        """
        Parse malloc_par's data and initialize the malloc_par object

        :param ptm: ptmalloc object
        :param addr: address for a malloc_par where to read the structure's content from the debugger
        :param mem: alternatively to "addr", provides the memory bytes of that malloc_par's content
        :param debugger: the pydbg object
        :param version: the glibc version
        """

        super(malloc_par, self).__init__(ptm, debugger=debugger)

        self.size = 0 # sizeof(struct malloc_par)
        self.invalid_ok = invalid_ok
    
        # malloc_par structure's fields, in this order for easy lookup
        # Note: commented ones have been added/removed at some point in glibc
        # so are not present in all glibc versions
        self.trim_threshold = 0
        self.top_pad = 0
        self.mmap_threshold = 0
        self.arena_test = 0
        self.arena_max = 0
        self.arena_stickiness = 0 # specific to photon 3.0
        self.n_mmaps = 0
        self.n_mmaps_max = 0
        self.max_n_mmaps = 0
        self.no_dyn_threshold = 0
        self.mmapped_mem = 0
        self.max_mmapped_mem = 0
        #self.max_total_mem = 0 # removed in 2.24
        self.sbrk_base = 0
        # below added in 2.26 when USE_TCACHE is set
        # self.tcache_bins = 0
        # self.tcache_max_bytes = 0
        # self.tcache_count = 0
        # self.tcache_unsorted_limit = 0

        if addr is None:
            if mem is None:
                pu.print_error("Please specify a struct malloc_par address")
                self.initOK = False
                return

            self.address = None
        else:
            self.address = addr

        if debugger is not None:
            self.dbg = debugger
        else:
            pu.print_error("Please specify a debugger")
            raise Exception("sys.exit()")

        if version is None:
            pu.print_error("Please specify a glibc version for malloc_par")
            raise Exception("sys.exit()")
        else:
            self.version = version

        self.initialize_sizes_and_offsets()

        if mem is None:
            # a string of raw memory was not provided, let's read it from the debugger
            try:
                self.mem = self.dbg.read_memory(addr, self.size)
            except TypeError:
                pu.print_error("Invalid address specified")
                self.initOK = False
                return
            except RuntimeError:
                pu.print_error("Could not read address {0:#x}".format(addr))
                self.initOK = False
                return
        else:
            if len(mem) < self.size:
                pu.print_error("Provided memory size is too small for a malloc_par")
                self.initOK = False
                return
            self.mem = mem[:self.size]

        self.unpack_memory()

    def initialize_sizes_and_offsets(self):
        """Initialize malloc_par's specific sizes based on the glibc version and architecture
        """

        self.size_sz = self.dbg.get_size_sz()

        if self.version < 2.15:
            # XXX - seems 2.14 has same fields as 2.15 so likely we can support
            # older easily...
            pu.print_error("Unsupported version for malloc_par")
            raise Exception('sys.exit()')

        if self.version >= 2.15 and self.version <= 2.23:
            if self.size_sz == 4:
                # sizeof(malloc_par) = 20 + 16 + 16
                self.size = 0x34
            elif self.size_sz == 8:
                # sizeof(malloc_par) = 40 + 16 + 32
                self.size = 0x58

        elif self.version >= 2.24 and self.version <= 2.25:
            # max_total_mem removed in 2.24
            if self.size_sz == 4:
                self.size = 0x30
            elif self.size_sz == 8:
                self.size = 0x50

        elif self.version >= 2.26:
            # tcache_* added in 2.26
            if self.ptm.is_tcache_enabled():
                # USE_TCACHE is set
                if self.size_sz == 4:
                    self.size = 0x40
                elif self.size_sz == 8:
                    self.size = 0x70
            else:
                # revert to same sizes as [2.24, 2.25] if USE_TCACHE not set
                if self.size_sz == 4:
                    self.size = 0x30
                elif self.size_sz == 8:
                    self.size = 0x50
            if self.ptm.distribution == "photon" and self.ptm.release == "3.0":
                # arena_stickiness added for all 2.28 versions
                self.size += self.size_sz

        log.debug(f"malloc_par.size = {self.size:#x}")

    def unpack_memory(self):
        """Actually parse all the malloc_par's fields from the memory bytes (previously retrieved)
        """

        if self.mem is None:
            pu.print_error("No memory found")
            raise Exception("sys.exit()")

        if self.size_sz == 4:
            fmt = "<I"
        elif self.size_sz == 8:
            fmt = "<Q"

        self.trim_threshold = self.unpack_variable(fmt, 0)
        self.top_pad = self.unpack_variable(fmt, self.size_sz)
        self.mmap_threshold = self.unpack_variable(fmt, self.size_sz * 2)
        self.arena_test = self.unpack_variable(fmt, self.size_sz * 3)
        self.arena_max = self.unpack_variable(fmt, self.size_sz * 4)
        if self.ptm.distribution == "photon" and self.ptm.release == "3.0":
            self.arena_stickiness = self.unpack_variable(fmt, self.size_sz * 5)
            offset = self.size_sz * 6
        else:
            offset = self.size_sz * 5

        # size shared on both 32bit and 64bit Intel
        fmt = "<I"

        self.n_mmaps = self.unpack_variable(fmt, offset)
        offset = offset + 4

        self.n_mmaps_max = self.unpack_variable(fmt, offset)
        offset = offset + 4

        self.max_n_mmaps = self.unpack_variable(fmt, offset)
        offset = offset + 4

        self.no_dyn_threshold = self.unpack_variable(fmt, offset)
        offset = offset + 4

        if self.size_sz == 4:
            fmt = "<I"
        elif self.size_sz == 8:
            fmt = "<Q"
        self.mmapped_mem = self.unpack_variable(fmt, offset)
        offset = offset + self.size_sz

        self.max_mmapped_mem = self.unpack_variable(fmt, offset)
        offset = offset + self.size_sz

        if self.version <= 2.23:
            # max_total_mem removed in 2.24
            self.max_total_mem = self.unpack_variable(fmt, offset)
            offset = offset + self.size_sz

        self.sbrk_base = self.unpack_variable(fmt, offset)
        offset = offset + self.size_sz

        # Sometimes sbrk_base isn't
        self.sbrk_base = self.sbrk_base + (self.CHUNK_ALIGNMENT - 1)
        self.sbrk_base = self.sbrk_base & (~(self.CHUNK_ALIGNMENT - 1))
        # self.sbrk_base += 0x8

        # Could not read sbrk_base from mp_, fall back to maps file
        # NOTE: can happen even on main_arena early before it gets initialized
        if not self.invalid_ok and (self.sbrk_base == 0 or self.sbrk_base is None):
            print("Getting heap base from proc")
            self.sbrk_base, end = self.dbg.get_heap_address()

        # We can't read heap address from mp_ or from maps file, exit
        if not self.invalid_ok and (self.sbrk_base == 0 or self.sbrk_base is None):
            pu.print_error("Could not find sbrk_base, this setup is unsupported.")
            raise Exception("sys.exit()")

        if self.ptm.is_tcache_enabled():
            # tcache_* added in 2.26 and USE_TCACHE set
            self.tcache_bins = self.unpack_variable(fmt, offset)
            self.tcache_max_bytes = self.unpack_variable(fmt, offset + self.size_sz)
            self.tcache_count = self.unpack_variable(fmt, offset + self.size_sz*2)
            self.tcache_unsorted_limit = self.unpack_variable(fmt, offset + self.size_sz*3)

    # XXX - fixme
    def write(self, inferior=None):
        """Write malloc_par's data into memory using debugger
        """
        pu.print_error("malloc_par write() not yet implemented.")

    def __str__(self):
        """Pretty printer for the malloc_par
        """

        title = "struct malloc_par @ 0x%x {" % self.address
        txt = pu.color_title(title)
        txt += "\n{:16} = ".format("trim_threshold")
        txt += pu.color_value("{:#x}".format(self.trim_threshold))
        txt += "\n{:16} = ".format("top_pad")
        txt += pu.color_value("{:#x}".format(self.top_pad))
        txt += "\n{:16} = ".format("mmap_threshold")
        txt += pu.color_value("{:#x}".format(self.mmap_threshold))
        txt += "\n{:16} = ".format("arena_test")
        txt += pu.color_value("{:#x}".format(self.arena_test))
        txt += "\n{:16} = ".format("arena_max")
        txt += pu.color_value("{:#x}".format(self.arena_max))
        if self.ptm.distribution == "photon" and self.ptm.release == "3.0":
            txt += "\n{:16} = ".format("arena_stickiness")
            txt += pu.color_value("{:#x}".format(self.arena_stickiness))
        txt += "\n{:16} = ".format("n_mmaps")
        txt += pu.color_value("{:#x}".format(self.n_mmaps))
        txt += "\n{:16} = ".format("n_mmaps_max")
        txt += pu.color_value("{:#x}".format(self.n_mmaps_max))
        txt += "\n{:16} = ".format("max_n_mmaps")
        txt += pu.color_value("{:#x}".format(self.max_n_mmaps))
        txt += "\n{:16} = ".format("no_dyn_threshold")
        txt += pu.color_value("{:#x}".format(self.no_dyn_threshold))
        txt += "\n{:16} = ".format("mmapped_mem")
        txt += pu.color_value("{:#x}".format(self.mmapped_mem))
        txt += "\n{:16} = ".format("max_mmapped_mem")
        txt += pu.color_value("{:#x}".format(self.max_mmapped_mem))
        if self.version <= 2.23:
            txt += "\n{:16} = ".format("max_total_mem")
            txt += pu.color_value("{:#x}".format(self.max_total_mem))
        txt += "\n{:16} = ".format("sbrk_base")
        txt += pu.color_value("{:#x}".format(self.sbrk_base))
        if self.ptm.is_tcache_enabled():
            txt += "\n{:16} = ".format("tcache_bins")
            txt += pu.color_value("{:#x}".format(self.tcache_bins))
            txt += "\n{:16} = ".format("tcache_max_bytes")
            txt += pu.color_value("{:#x}".format(self.tcache_max_bytes))
            txt += "\n{:16} = ".format("tcache_count")
            txt += pu.color_value("{:#x}".format(self.tcache_count))
            txt += "\n{:16} = ".format("tcache_unsorted_limit")
            txt += pu.color_value("{:#x}".format(self.tcache_unsorted_limit))
        return txt

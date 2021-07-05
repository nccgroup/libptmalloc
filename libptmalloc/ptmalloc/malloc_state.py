import struct
import sys
import importlib

import libptmalloc.frontend.printutils as pu
importlib.reload(pu)
import libptmalloc.ptmalloc.heap_structure as hs
importlib.reload(hs)

class malloc_state(hs.heap_structure):
    "python representation of a struct malloc_state"

    # XXX - we can probably get the version directly from the ptm argument?
    def __init__(self, ptm, addr=None, mem=None, debugger=None, version=None):
        """
        Parse malloc_state's data and initialize the malloc_state object

        :param ptm: ptmalloc object
        :param addr: address for a malloc_state where to read the structure's content from the debugger
        :param mem: alternatively to "addr", provides the memory bytes of that malloc_state's content
        :param debugger: the pydbg object
        :param version: the glibc version
        """

        super(malloc_state, self).__init__(ptm, debugger=debugger)

        self.size = 0 # sizeof(struct malloc_state)

        # malloc_state structure's fields, in this order for easy lookup
        # Note: commented ones have been added at some point in glibc
        # so are not present in older glibc versions
        self.mutex = 0
        self.flags = 0
        # self.have_fastchunks = 0 # added in 2.27
        self.fastbinsY = 0
        self.top = 0
        self.last_remainder = 0
        self.bins = 0
        self.binmap = 0
        self.next = 0
        self.next_free = 0
        # self.attached_threads = 0 # added in 2.23
        self.system_mem = 0
        self.max_system_mem = 0

        # helpers
        self.fastbins_offset = 0
        self.bins_offset = 0

        if addr is None:
            if mem is None:
                pu.print_error("Please specify a struct malloc_state address")
                self.initOK = False
                return

            self.address = None
        else:
            self.address = addr

        if debugger is not None:
            self.dbg = debugger
        else:
            pu.print_error("Please specify a debugger")
            raise Exception('sys.exit()')

        if version is None:
            pu.print_error("Please specify a glibc version for malloc_state")
            raise Exception('sys.exit()')
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
                pu.print_error("Provided memory size is too small for a malloc_state")
                self.initOK = False
                return
            self.mem = mem[:self.size]

        self.unpack_memory()

    def initialize_sizes_and_offsets(self):
        """Initialize malloc_state's specific sizes based on the glibc version and architecture
        """

        self.size_sz = self.dbg.get_size_sz()

        if self.version < 2.15:
            # XXX - seems 2.14 has same fields as 2.15 so likely we can support
            # older easily...
            pu.print_error("Unsupported version for malloc_state")
            raise Exception('sys.exit()')

        if self.version >= 2.15 and self.version < 2.23:
            if self.size_sz == 4:
                # sizeof(malloc_state) = 4+4+40+4+4+(254*4)+16+4+4+4+4
                self.size = 0x450
            elif self.size_sz == 8:
                # sizeof(malloc_state) = 4+4+80+8+8+(254*8)+16+8+8+8+8
                self.size = 0x888

            self.fastbins_offset = 8
            self.bins_offset = self.fastbins_offset + 12 * self.size_sz
        
        elif self.version >= 2.23 and self.version <= 2.25:
            # attached_threads added in 2.23
            if self.size_sz == 4:
                self.size = 0x454
            elif self.size_sz == 8:
                self.size = 0x890

            self.fastbins_offset = 8
            self.bins_offset = self.fastbins_offset + 12 * self.size_sz
        
        elif self.version >= 2.27:
            # have_fastchunks added in 2.27
            if self.size_sz == 4:
                # hax, empiric: +4 for padding added after fastbinsY[]
                self.size = 0x458+4
                self.fastbins_offset = 0xC
            elif self.size_sz == 8:
                self.size = 0x898
                self.fastbins_offset = 0x10

            self.bins_offset = self.fastbins_offset + 12 * self.size_sz

    def unpack_memory(self):
        """Actually parse all the malloc_state's fields from the memory bytes (previously retrieved)
        """

        if self.mem is None:
            pu.print_error("No memory found")
            raise Exception('sys.exit()')

        self.mutex = self.unpack_variable("<I", 0)
        self.flags = self.unpack_variable("<I", 4)
        offset = 8

        if self.version >= 2.27:
            # have_fastchunks added in 2.27
            if self.size_sz == 4:
                fmt = "<I"
            elif self.size_sz == 8:
                fmt = "<Q"
            # this is padded on 64-bit despite being int
            self.have_fastchunks = self.unpack_variable(fmt, offset)
            offset = offset + self.size_sz

        if self.size_sz == 4:
            fmt = "<10I"
        elif self.size_sz == 8:
            fmt = "<10Q"
        self.fastbinsY = struct.unpack_from(fmt, self.mem, offset)
        offset = offset + 10 * self.size_sz
        if self.version >= 2.27:
            if self.size_sz == 4:
                # hax, empiric: +4 for padding added after fastbinsY[]
                offset += 4

        if self.size_sz == 4:
            fmt = "<I"
        elif self.size_sz == 8:
            fmt = "<Q"
        self.top = self.unpack_variable(fmt, offset)
        offset += self.size_sz

        self.last_remainder = self.unpack_variable(fmt, offset)
        offset = offset + self.size_sz

        if self.size_sz == 4:
            fmt = "<254I"
        elif self.size_sz == 8:
            fmt = "<254Q"
        self.bins = struct.unpack_from(fmt, self.mem, offset)
        offset = offset + (254 * self.size_sz)
    
        self.binmap = struct.unpack_from("<IIII", self.mem, offset)
        offset = offset + 16

        if self.size_sz == 4:
            fmt = "<I"
        elif self.size_sz == 8:
            fmt = "<Q"
        self.next = self.unpack_variable(fmt, offset)
        offset = offset + self.size_sz

        self.next_free = self.unpack_variable(fmt, offset)
        offset = offset + self.size_sz

        if self.version >= 2.23:
            # attached_threads added in 2.23
            self.attached_threads = self.unpack_variable(fmt, offset)
            offset = offset + self.size_sz

        self.system_mem = self.unpack_variable(fmt, offset)
        offset = offset + self.size_sz

        self.max_system_mem = self.unpack_variable(fmt, offset)

    # XXX - this is probably broken as we haven't used it yet
    def write(self, inferior=None):
        """Write malloc_state's data into memory using debugger
        """

        if self.size_sz == 4:
            mem = struct.pack(
                "<275I",
                self.mutex,
                self.flags,
                self.fastbinsY,
                self.top,
                self.last_remainder,
                self.bins,
                self.binmap,
                self.next,
                self.system_mem,
                self.max_system_mem,
            )
        elif self.size_sz == 8:
            mem = struct.pack(
                "<II266QIIIIQQQ",
                self.mutex,
                self.flags,
                self.fastbinsY,
                self.top,
                self.last_remainder,
                self.bins,
                self.binmap,
                self.next,
                self.system_mem,
                self.max_system_mem,
            )

        if self.dbg is not None:
            self.dbg.write_memory(self.address, mem)
        elif inferior is not None:
            self.inferior.write_memory(self.address, mem)

    def __str__(self):
        """Pretty printer for the malloc_state
        """
        return self.to_string()

    def to_string(self, verbose=0, use_cache=False):
        """Pretty printer for the malloc_state supporting different level of verbosity

        :param verbose: 0 for non-verbose. 1 for more verbose. 2 for even more verbose.
        :param use_cache: True if we want to use the cached information from the cache object.
                          False if we want to fetch the data again
        """

        title = "struct malloc_state @ 0x%x {" % self.address
        txt = pu.color_title(title)
        txt += "\n{:16} = ".format("mutex")
        txt += pu.color_value("{:#x}".format(self.mutex))
        txt += "\n{:16} = ".format("flags")
        txt += pu.color_value("{:#x}".format(self.flags))
        if self.version >= 2.27:
            txt += "\n{:16} = ".format("have_fastchunks")
            txt += pu.color_value("{:#x}".format(self.have_fastchunks))
        txt += self.fastbins_to_string(verbose=verbose, use_cache=use_cache)
        txt += "\n{:16} = ".format("top")
        txt += pu.color_value("{:#x}".format(self.top))
        txt += "\n{:16} = ".format("last_remainder")
        txt += pu.color_value("{:#x}".format(self.last_remainder))
        txt += self.bins_to_string(verbose=verbose, use_cache=use_cache)
        if verbose > 0:
            for i in range(len(self.binmap)):
                txt += "\n{:16} = ".format("binmap[%d]" % i)
                txt += pu.color_value("{:#x}".format(self.binmap[i]))
        else:
            txt += "\n{:16} = ".format("binmap")
            txt += pu.color_value("{}".format("{...}"))
        txt += "\n{:16} = ".format("next")
        txt += pu.color_value("{:#x}".format(self.next))
        txt += "\n{:16} = ".format("next_free")
        txt += pu.color_value("{:#x}".format(self.next_free))
        if self.version >= 2.23:
            txt += "\n{:16} = ".format("attached_threads")
            txt += pu.color_value("{:#x}".format(self.attached_threads))
        txt += "\n{:16} = ".format("system_mem")
        txt += pu.color_value("{:#x}".format(self.system_mem))
        txt += "\n{:16} = ".format("max_system_mem")
        txt += pu.color_value("{:#x}".format(self.max_system_mem))
        return txt

    def fastbins_to_string(self, show_status=False, verbose=2, use_cache=False):
        """Pretty printer for the malloc_state.fastbinsY[] array supporting different level of verbosity

        :param verbose: 0 for non-verbose. 1 for more verbose. 2 for even more verbose.
        :param use_cache: True if we want to use the cached information from the cache object.
                          False if we want to fetch the data again
        """

        self.ptm.cache.update_fast_bins(show_status=show_status, use_cache=use_cache)

        txt = ""
        if verbose == 0:
            txt += "\n{:16} = ".format("fastbinsY")
            txt += pu.color_value("{}".format("{...}"))
            return txt
        elif verbose == 1:
            show_empty = False
        elif verbose >= 2:
            show_empty = True
        else:
            raise Exception("Wrong verbosity passed to fastbins_to_string()")

        for i in range(len(self.fastbinsY)):
            count = len(self.ptm.cache.fast_bins[i])
            if show_empty or count > 0:
                txt += "\n{:16} = ".format("fastbinsY[%d]" % i)
                txt += pu.color_value("{:#x}".format(self.fastbinsY[i]))
                txt += " (sz {:#x})".format(self.ptm.fast_bin_size(i))
                msg = "entry"
                if count > 1:
                    msg = "entries"
                if count == 0:
                    txt += " [EMPTY]"
                else:
                    txt += " [{:#d} {}]".format(count, msg)
        return txt

    def bins_to_string(self, show_status=False, verbose=2, use_cache=False):
        """Pretty printer for the malloc_state.bins[] array supporting different level of verbosity

        :param verbose: 0 for non-verbose. 1 for more verbose. 2 for even more verbose.
        :param use_cache: True if we want to use the cached information from the cache object.
                          False if we want to fetch the data again
        """

        self.ptm.cache.update_bins(show_status=show_status, use_cache=use_cache)
        mstate = self.ptm.cache.mstate

        txt = ""
        if verbose == 0:
            txt += "\n{:16} = ".format("bins")
            txt += pu.color_value("{}".format("{...}"))
            return txt
        elif verbose == 1:
            show_empty = False
        elif verbose >= 2:
            show_empty = True
        else:
            raise Exception("Wrong verbosity passed to bins_to_string()")

        for i in range(len(self.ptm.cache.bins)):
            count = len(self.ptm.cache.bins[i])
            if show_empty or count > 0:
                txt += "\n{:16} = ".format("bins[%d]" % i)
                txt += pu.color_value("{:#x}, {:#x}".format(mstate.bins[i*2], mstate.bins[i*2+1]))
                size = self.ptm.bin_size(i)
                if i == self.ptm.bin_index_unsorted:
                    txt += " (unsorted)"
                elif i <= self.ptm.bin_index_small_max:
                    txt += " (small sz 0x%x)" % size
                elif i <= self.ptm.bin_index_large_max:
                    txt += " (large sz 0x%x)" % size
                elif i == self.ptm.bin_index_uncategorized:
                    # size == None
                    txt += " (large uncategorized)"

                msg = "entry"
                if count > 1:
                    msg = "entries"
                if count == 0:
                    txt += " [EMPTY]"
                else:
                    txt += " [{:#d} {}]".format(count, msg)
        return txt
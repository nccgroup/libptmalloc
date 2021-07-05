import struct
import sys
import importlib
import logging

import libptmalloc.frontend.printutils as pu
importlib.reload(pu)
import libptmalloc.ptmalloc.heap_structure as hs
importlib.reload(hs)

log = logging.getLogger("libptmalloc")
log.trace("tcache_perthread.py")

class tcache_perthread(hs.heap_structure):
    """"python representation of a struct tcache_perthread_struct.
    Note: tcache was added in glibc 2.26"""

    # XXX - we can probably get the version directly from the ptm argument?
    def __init__(self, ptm, addr=None, mem=None, debugger=None, version=None):
        """
        Parse tcache_perthread_struct's data and initialize the tcache_perthread object

        :param ptm: ptmalloc object
        :param addr: address for a tcache_perthread_struct where to read the structure's content from the debugger
        :param mem: alternatively to "addr", provides the memory bytes of that tcache_perthread_struct's content
        :param debugger: the pydbg object
        :param version: the glibc version
        """

        super(tcache_perthread, self).__init__(ptm, debugger=debugger)

        self.size = 0 # sizeof(struct tcache_perthread_struct)
    
        self.counts = []
        self.entries = []

        if addr is None:
            if mem is None:
                pu.print_error("Please specify a struct tcache_perthread address")
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
            pu.print_error("Please specify a glibc version for tcache_perthread")
            raise Exception("sys.exit()")
        else:
            self.version = version

        if version <= 2.25:
            pu.print_error("tcache was added in glibc 2.26. Wrong version configured?")
            raise Exception("sys.exit()")
        if not self.ptm.is_tcache_enabled():
            pu.print_error("tcache is configured as disabled. Wrong configuration?")
            raise Exception("sys.exit()")

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
                pu.print_error("Provided memory size is too small for a tcache_perthread")
                self.initOK = False
                return
            self.mem = mem[:self.size]

        self.unpack_memory()

    def initialize_sizes_and_offsets(self):
        """Initialize tcache_perthread_struct's specific sizes based on the glibc version and architecture
        """

        self.size_sz = self.dbg.get_size_sz()

        if self.size_sz == 4:
            # sizeof(tcache_perthread_struct) = 64+64*4
            self.size = 0x140
        elif self.size_sz == 8:
            # sizeof(tcache_perthread_struct) = 64+64*8
            self.size = 0x240

        log.debug(f"tcache_perthread_struct.size = {self.size:#x}")

    def unpack_memory(self):
        """Actually parse all the tcache_perthread_struct's fields from the memory bytes (previously retrieved)
        """

        if self.mem is None:
            pu.print_error("No memory found")
            raise Exception("sys.exit()")

        self.counts = struct.unpack_from("64B", self.mem, 0)
        offset = 64

        if self.size_sz == 4:
            fmt = "<64I"
        elif self.size_sz == 8:
            fmt = "<64Q"
        self.entries = struct.unpack_from(fmt, self.mem, offset)
        offset = offset + 64 * self.size_sz

    # XXX - fixme
    def write(self, inferior=None):
        """Write tcache_perthread_struct's data into memory using debugger
        """
        pu.print_error("tcache_perthread write() not yet implemented.")

    def __str__(self):
        """Pretty printer for the tcache_perthread_struct
        """
        return self.to_string()

    def to_string(self, verbose=False):
        """Pretty printer for the tcache_perthread_struct supporting different level of verbosity

        :param verbose: False for non-verbose. True for more verbose
        """

        title = "struct tcache_perthread_struct @ 0x%x {" % self.address
        txt = pu.color_title(title)
        for i in range(len(self.counts)):
            if verbose or self.counts[i] > 0:
                curr_size = self.ptm.tcache_bin_size(i)
                txt += "\n{:11} = ".format("counts[%d]" % i)
                txt += pu.color_value("{:#d}".format(self.counts[i]))
                txt += " (sz {:#x})".format(curr_size)
        for i in range(len(self.entries)):
            if verbose or self.entries[i] != 0:
                curr_size = self.ptm.tcache_bin_size(i)
                txt += "\n{:11} = ".format("entries[%d]" % i)
                txt += pu.color_value("{:#x}".format(self.entries[i]))
                txt += " (sz {:#x})".format(curr_size)
        return txt

    def to_summary_string(self, verbose=False):
        """Pretty printer for the tcache_perthread_struct supporting different level of verbosity
        with a simplified output. We don't show the tcache_perthread_struct.count values
        but instead print them in front of their associated tcache_perthread_struct.entries[]

        :param verbose: False for non-verbose. True for more verbose
        """

        title = "struct tcache_perthread_struct @ 0x%x {" % self.address
        txt = pu.color_title(title)
        #txt += "\n{:11} = {}".format("counts[]", "{...}")
        for i in range(len(self.entries)):
            if verbose or self.entries[i] != 0:
                curr_size = self.ptm.tcache_bin_size(i)
                txt += "\n{:11} = ".format("entries[%d]" % i)
                txt += pu.color_value("{:#x}".format(self.entries[i]))
                txt += " (sz {:#x})".format(curr_size)
                msg = "entry"
                if self.counts[i] > 1:
                    msg = "entries"
                if self.counts[i] == 0:
                    txt += " [EMPTY]"
                else:
                    txt += " [{:#d} {}]".format(self.counts[i], msg)
        return txt

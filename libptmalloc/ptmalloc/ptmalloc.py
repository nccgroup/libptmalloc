import struct
import sys
import importlib
import logging
from enum import Enum, auto

import libptmalloc.frontend.printutils as pu
importlib.reload(pu)
import libptmalloc.ptmalloc.malloc_state as ms
importlib.reload(ms)
import libptmalloc.ptmalloc.malloc_chunk as mc
importlib.reload(mc)
import libptmalloc.ptmalloc.cache as c
importlib.reload(c)

log = logging.getLogger("libptmalloc")
log.trace("ptmalloc.py")

class chunk_type(Enum):
    INUSE = auto() # == 1
    FREE_SMALL = auto()
    FREE_LARGE = auto()
    FREE_FAST = auto()
    FREE_TCACHE = auto()

class ptmalloc:
    def __init__(self, SIZE_SZ=None, debugger=None, version=None, tcache_enabled=None):
        """
        :param debugger: the pydbg object
        :param version: the glibc version
        :param tcache_enabled: False if tcache disabled on a glibc >= 2.26 (USE_TCACHE not set)
                              It should never be True on glibc < 2.26 afaict
                              None means assume glibc >= 2.26 => tcache enabled
                                               glibc < 2.26 => tcache disable
        """

        self.terse = True  # XXX - This should be configurable
        self.SIZE_SZ = SIZE_SZ

        self.NBINS = 128
        self.NSMALLBINS = 64 # this is wrong and should not be used!
        self.BINMAPSHIFT = 5
        self.FASTCHUNKS_BIT = 0x1
        self.NONCONTIGUOUS_BIT = 0x2
        self.HEAP_MIN_SIZE = 32 * 1024
        self.HEAP_MAX_SIZE = 1024 * 1024
        self.BITSPERMAP = 1 << self.BINMAPSHIFT
        self.BINMAPSIZE = self.NBINS / self.BITSPERMAP
        self.TCACHE_MAX_BINS = 64

        self.PREV_INUSE = 1
        self.IS_MMAPPED = 2
        self.NON_MAIN_ARENA = 4
        self.SIZE_BITS = self.PREV_INUSE | self.IS_MMAPPED | self.NON_MAIN_ARENA

        self.ptchunk_callback = None
        self.ptchunk_callback_cached = None

        self.cache = c.cache(self)

        self.dbg = debugger
        self.version = version  # glibc version
        self.tcache_enabled = tcache_enabled
        self.tcache_available = tcache_enabled
        self.distribution = None # the Linux distribution (e.g. "photon")
        self.release = None #  # the release for that Linux distribution (e.g. "3.0" for "photon")
        self.set_globals(SIZE_SZ=self.SIZE_SZ)

    def set_globals(self, SIZE_SZ=None):
        if SIZE_SZ is None:
            if self.dbg is None:
                pu.print_error("Please specify a SIZE_SZ value or run in debugger.")
                raise Exception("sys.exit()")

            self.SIZE_SZ = self.dbg.get_size_sz()
            if self.SIZE_SZ is None:
                pu.print_error("error fetching size")
                raise Exception("sys.exit()")
        else:
            self.SIZE_SZ = SIZE_SZ

        self.MIN_CHUNK_SIZE = 4 * self.SIZE_SZ
        self.MALLOC_ALIGNMENT = 2 * self.SIZE_SZ
        self.MALLOC_ALIGN_MASK = self.MALLOC_ALIGNMENT - 1
        self.MINSIZE = (
            self.MIN_CHUNK_SIZE + self.MALLOC_ALIGN_MASK
        ) & ~self.MALLOC_ALIGN_MASK

        self.SMALLBIN_WIDTH = self.MALLOC_ALIGNMENT
        self.SMALLBIN_CORRECTION = int(self.MALLOC_ALIGNMENT > (2 * self.SIZE_SZ))
        self.MIN_LARGE_SIZE = self.NSMALLBINS * self.SMALLBIN_WIDTH # this is wrong and should not be used!

        self.MAX_FAST_SIZE = 80 * self.SIZE_SZ / 4
        size = self.request2size(self.MAX_FAST_SIZE)
        self.NFASTBINS = self.fast_bin_index(size) + 1

        self.INUSE_HDR_SZ = 2 * self.SIZE_SZ
        self.FREE_TCACHE_HDR_SZ = 4 * self.SIZE_SZ
        self.FREE_FASTCHUNK_HDR_SZ = 3 * self.SIZE_SZ
        self.FREE_HDR_SZ = 4 * self.SIZE_SZ
        self.FREE_LARGE_HDR_SZ = 6 * self.SIZE_SZ

        self.tcache_available = self.dbg.is_tcache_available()
        
        # indexes in malloc_state.bin[] to ease use everywhere
        self.bin_index_unsorted = 0
        self.bin_index_small_max = 62 # small are 1 to 62
        self.bin_index_large_max = 125 # large are 63 to 126
        self.bin_index_uncategorized = 126

        # print(f"SIZE_SZ = {self.SIZE_SZ:#x}")
        # print(f"MALLOC_ALIGNMENT = {self.MALLOC_ALIGNMENT:#x}")
        # print(f"MINSIZE = {self.MINSIZE:#x}")

    def chunk2mem(self, p):
        "conversion from malloc header to user pointer"
        return p.address + (2 * self.SIZE_SZ)

    def mem2chunk(self, mem):
        "conversion from user pointer to malloc header"
        return mem - (2 * self.SIZE_SZ)

    def request2size(self, req):
        "pad request bytes into a usable size"

        if req + self.SIZE_SZ + self.MALLOC_ALIGN_MASK < self.MINSIZE:
            return self.MINSIZE
        else:
            return (
                int(req + self.SIZE_SZ + self.MALLOC_ALIGN_MASK)
                & ~self.MALLOC_ALIGN_MASK
            )

    def fastbin(self, mstate, idx):
        return mstate.fastbinsY[idx]

    def top(self, mstate):
        return mstate.top

    def heap_for_ptr(self, ptr):
        "find the heap and corresponding arena for a given ptr"
        return ptr & ~(self.HEAP_MAX_SIZE - 1)

    def chunksize(self, p):
        "Get size, ignoring use bits"
        return p.size & ~self.SIZE_BITS

    def mutex_lock(self, mstate):
        mstate.mutex = 1
        try:
            self.dbg.write_memory(mstate.address, struct.pack("<I", mstate.mutex))
        except:
            # write_memory does not work on core dumps, but we also don't need
            # to lock the mutex there
            pass

    def mutex_unlock(self, mstate):
        mstate.mutex = 0
        try:
            self.dbg.write_memory(mstate.address, struct.pack("<I", mstate.mutex))
        except:
            pass

    def prev_inuse(self, p):
        "extract inuse bit of previous chunk"
        return p.size & self.PREV_INUSE

    def chunk_is_mmapped(self, p):
        "check for mmap()'ed chunk"
        return p.size & self.IS_MMAPPED

    def chunk_non_main_arena(self, p):
        "check for chunk from non-main arena"
        return p.size & self.NON_MAIN_ARENA

    def next_chunk(self, p):
        "Ptr to next physical malloc_chunk."
        return p.address + (p.size & ~self.SIZE_BITS)

    def prev_chunk(self, p):
        "Ptr to previous physical malloc_chunk"
        return p.address - p.prev_size

    def chunk_at_offset(self, p, s):
        "Treat space at ptr + offset as a chunk"
        return mc.malloc_chunk(self, p.address + s, inuse=False, debugger=self.dbg)

    def inuse(self, p):
        """extract p's inuse bit
        
        XXX - should we get rid of this function and just rely on the malloc_chunk.inuse instead
        since we parsed it already and it avoids building yet another malloc_chunk
        with tcache/fast arrays potential slow lookup?
        """
        # There won't be a valid following chunk so better to rely on that
        if p.is_top:
            return True
        # General case
        return (
            mc.malloc_chunk(
                self,
                addr=p.address + (p.size & ~self.SIZE_BITS),
                inuse=False,
                debugger=self.dbg,
            ).size
            & self.PREV_INUSE
        )

    def set_inuse(self, p):
        "set chunk as being inuse without otherwise disturbing"
        chunk = mc.malloc_chunk(
            self,
            (p.address + (p.size & ~self.SIZE_BITS)),
            inuse=False,
            debugger=self.dbg,
        )
        chunk.size |= self.PREV_INUSE
        chunk.write()

    def clear_inuse(self, p):
        "clear chunk as being inuse without otherwise disturbing"
        chunk = mc.malloc_chunk(
            self,
            addr=(p.address + (p.size & ~self.SIZE_BITS)),
            inuse=False,
            debugger=self.dbg,
        )
        chunk.size &= ~self.PREV_INUSE
        chunk.write()

    def inuse_bit_at_offset(self, p, s):
        "check inuse bits in known places"
        return (
            mc.malloc_chunk(
                self, addr=(p.address + s), inuse=False, debugger=self.dbg
            ).size
            & self.PREV_INUSE
        )

    def set_inuse_bit_at_offset(self, p, s):
        "set inuse bits in known places"
        chunk = mc.malloc_chunk(self, addr=(p.address + s), inuse=False, debugger=self.dbg)
        chunk.size |= self.PREV_INUSE
        chunk.write()

    def clear_inuse_bit_at_offset(self, p, s):
        "clear inuse bits in known places"
        chunk = mc.malloc_chunk(self, addr=(p.address + s), inuse=False, debugger=self.dbg)
        chunk.size &= ~self.PREV_INUSE
        chunk.write()

    def bin_at(self, m, i):
        "addressing -- note that bin_at(0) does not exist"

        if i == 0:
            pu.print_error("bin_at(0) does not exist")
            raise Exception("sys.exit()")

        index = (i - 1) * 2
        return m.bins[index]

    def next_bin(self, b):
        return b + 1

    # XXX - These names are stupid
    def first(self, b):
        return b.fd

    def last(self, b):
        return b.bk

    def in_smallbin_range(self, size):
        """Python implementation of glibc in_smallbin_range() macro

        NOTE: the test done in the in_smallbin_range() C macro does not work for
        us due to a disparity between 32-bit and 64-bit, see small_bin_index_32()
        and small_bin_index_64()
        """
        #return size < self.MIN_LARGE_SIZE
        if self.SIZE_SZ == 4:
            # following size in large bin is: 0x3f0
            return size <= 0x3e0
        elif self.SIZE_SZ == 8:
            # following size in large bin is: 0x430
            return size <= 0x3f0


    def have_fastchunks(self, M):
        return (M.flags & self.FASTCHUNKS_BIT) == 0

    def clear_fastchunks(self, M):
        M.flags |= self.FASTCHUNKS_BIT
        self.dbg.write_memory(M.address, struct.pack("<I", M.flags))

    def set_fastchunks(self, M):
        M.flags &= ~self.FASTCHUNKS_BIT
        self.dbg.write_memory(M.address, struct.pack("<I", M.flags))

    def contiguous(self, M):
        return (M.flags & self.NONCONTIGUOUS_BIT) == 0

    def noncontiguous(self, M):
        return (M.flags & self.NONCONTIGUOUS_BIT) != 0

    def set_noncontiguous(self, M):
        M.flags |= self.NONCONTIGUOUS_BIT
        self.dbg.write_memory(M.address, struct.pack("<I", M.flags))

    def set_contiguous(self, M):
        M.flags &= ~self.NONCONTIGUOUS_BIT
        self.dbg.write_memory(M.address, struct.pack("<I", M.flags))

    def get_max_fast(self):
        return self.dbg.parse_and_eval("global_max_fast")
    
    def tidx2usize(self, idx):
        """Python implementation of glibc tidx2usize() macro
        Convert an index in tcache bin array into the corresponding tcache bin size

        NOTE: not useful, as we use tcache_bin_size_XX() functions
        """
        return idx * self.MALLOC_ALIGNMENT + self.MINSIZE - self.SIZE_SZ

    def chunk_info(self, p, inuse_override=None, colorize_func=str, first_address=None, address_offset=False):
        info = []
        if address_offset is True and first_address is not None:
            info.append(colorize_func("0x%lx " % (p.address - first_address)))
        else:
            info.append(colorize_func("0x%lx " % p.address))
        if p.type == chunk_type.FREE_FAST:
            info.append("f ")
        elif p.type == chunk_type.FREE_TCACHE:
            info.append("t ")
        elif p.type == chunk_type.INUSE:
            info.append("M ")
        else:
            info.append("F ")
        sz = self.chunksize(p)
        if sz == 0:
            print("[!] Chunk at address 0x%.x likely invalid or corrupt" % p.address)
        if self.terse:
            info.append("sz:0x%.05x " % sz)
        else:
            info.append("sz:0x%.08x " % sz)
        flag_str = ""
        if self.terse:
            info.append("fl:")
            if self.chunk_is_mmapped(p):
                flag_str += "M"
            else:
                flag_str += "-"
            if self.chunk_non_main_arena(p):
                flag_str += "N"
            else:
                flag_str += "-"
            if self.prev_inuse(p):
                flag_str += "P"
            else:
                flag_str += "-"
            info.append("%3s" % flag_str)

        else:
            info.append("flags: ")
            if self.chunk_is_mmapped(p):
                flag_str += "MMAPPED"
            else:
                flag_str += "-------"
            flag_str += "|"
            if self.chunk_non_main_arena(p):
                flag_str += "NON_MAIN_ARENA"
            else:
                flag_str += "--------------"
            flag_str += "|"
            if self.prev_inuse(p):
                flag_str += "PREV_INUSE"
            else:
                flag_str += "----------"
            info.append("%33s" % flag_str)

        if self.ptchunk_callback != None:
            size = self.chunksize(p) - p.hdr_size
            if p.data_address != None:
                # We can provide an excess of information and the
                # callback can choose what to use
                cbinfo = {}
                # XXX - Don't know if we need to send all this
                cbinfo["caller"] = "ptchunk_info"
                cbinfo["allocator"] = "ptmalloc"
                cbinfo["addr"] = p.data_address
                cbinfo["hdr_sz"] = p.hdr_size
                cbinfo["chunksz"] = self.chunksize(p)
                cbinfo["min_hdr_sz"] = self.INUSE_HDR_SZ
                cbinfo["data_size"] = size
                # Sometimes we want to show free_pc even when a chunk is
                # in-use, like if we hook free to trace it
                cbinfo["inuse"] = p.inuse
                if inuse_override != None:
                    cbinfo["inuse_override"] = inuse_override
                cbinfo["no_print"] = True
                cbinfo["chunk_info"] = True
                cbinfo["size_sz"] = self.SIZE_SZ
                if p.from_mem:
                    cbinfo["mem"] = p.mem[p.hdr_size :]

                extra = self.ptchunk_callback(cbinfo)
                if extra:
                    info.append(" " + extra)

        # XXX - this breaks the "ptlist" output so commenting for now
        #info.append("\b")
        return "".join(info)

    def ptr_from_ptmalloc_chunk(self, p):
        return p.address + (self.SIZE_SZ * 2)
    
    def is_tcache_enabled(self):
        """tcache added in glibc 2.26
        but is only enabled if USE_TCACHE is set in the source code
        """
        if self.version < 2.26 or self.tcache_enabled is False:
            return False
        # We should never have version < 2.26 but tcache_enabled == true
        # so above is safe
        return True

    ########################################################
    # Everything below is related to bin sizes and indexes #
    ########################################################

    # The glibc source code has C macros to convert indexes to sizes but it seems
    # they are user-specified sizes, not actual chunks' sizes, and checking empirically
    # it was easier and more useful to just hardcode all the sizes/indexes directly
    # in the functions, separating 32-bit and 64-bit. This can serve as a reference
    # to know the exact chunks' sizes.
    # Also see https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/
    
    #
    # tcache bins
    #

    def tcache_bin_size_32(self, idx):
        """
        Convert an index in tcache bin array into a chunk size (32-bit)
        """
        if idx == 0:
            return 0x10
        elif idx == 1:
            return 0x20
        elif idx == 2:
            return 0x30
        elif idx == 3:
            return 0x40
        elif idx == 4:
            return 0x50
        elif idx == 5:
            return 0x60
        elif idx == 6:
            return 0x70
        elif idx == 7:
            return 0x80
        elif idx == 8:
            return 0x90
        elif idx == 9:
            return 0xa0
        elif idx == 10:
            return 0xb0
        elif idx == 11:
            return 0xc0
        elif idx == 12:
            return 0xd0
        elif idx == 13:
            return 0xe0
        elif idx == 14:
            return 0xf0
        elif idx == 15:
            return 0x100
        elif idx == 16:
            return 0x110
        elif idx == 17:
            return 0x120
        elif idx == 18:
            return 0x130
        elif idx == 19:
            return 0x140
        elif idx == 20:
            return 0x150
        elif idx == 21:
            return 0x160
        elif idx == 22:
            return 0x170
        elif idx == 23:
            return 0x180
        elif idx == 24:
            return 0x190
        elif idx == 25:
            return 0x1a0
        elif idx == 26:
            return 0x1b0
        elif idx == 27:
            return 0x1c0
        elif idx == 28:
            return 0x1d0
        elif idx == 29:
            return 0x1e0
        elif idx == 30:
            return 0x1f0
        elif idx == 31:
            return 0x200
        elif idx == 32:
            return 0x210
        elif idx == 33:
            return 0x220
        elif idx == 34:
            return 0x230
        elif idx == 35:
            return 0x240
        elif idx == 36:
            return 0x250
        elif idx == 37:
            return 0x260
        elif idx == 38:
            return 0x270
        elif idx == 39:
            return 0x280
        elif idx == 40:
            return 0x290
        elif idx == 41:
            return 0x2a0
        elif idx == 42:
            return 0x2b0
        elif idx == 43:
            return 0x2c0
        elif idx == 44:
            return 0x2d0
        elif idx == 45:
            return 0x2e0
        elif idx == 46:
            return 0x2f0
        elif idx == 47:
            return 0x300
        elif idx == 48:
            return 0x310
        elif idx == 49:
            return 0x320
        elif idx == 50:
            return 0x330
        elif idx == 51:
            return 0x340
        elif idx == 52:
            return 0x350
        elif idx == 53:
            return 0x360
        elif idx == 54:
            return 0x370
        elif idx == 55:
            return 0x380
        elif idx == 56:
            return 0x390
        elif idx == 57:
            return 0x3a0
        elif idx == 58:
            return 0x3b0
        elif idx == 59:
            return 0x3c0
        elif idx == 60:
            return 0x3d0
        elif idx == 61:
            return 0x3e0
        elif idx == 62:
            return 0x3f0
        elif idx == 63:
            return 0x400
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def tcache_bin_size_64(self, idx):
        """
        Convert an index in tcache bin array into a chunk size (64-bit)
        """
        if idx == 0:
            return 0x20
        elif idx == 1:
            return 0x30
        elif idx == 2:
            return 0x40
        elif idx == 3:
            return 0x50
        elif idx == 4:
            return 0x60
        elif idx == 5:
            return 0x70
        elif idx == 6:
            return 0x80
        elif idx == 7:
            return 0x90
        elif idx == 8:
            return 0xa0
        elif idx == 9:
            return 0xb0
        elif idx == 10:
            return 0xc0
        elif idx == 11:
            return 0xd0
        elif idx == 12:
            return 0xe0
        elif idx == 13:
            return 0xf0
        elif idx == 14:
            return 0x100
        elif idx == 15:
            return 0x110
        elif idx == 16:
            return 0x120
        elif idx == 17:
            return 0x130
        elif idx == 18:
            return 0x140
        elif idx == 19:
            return 0x150
        elif idx == 20:
            return 0x160
        elif idx == 21:
            return 0x170
        elif idx == 22:
            return 0x180
        elif idx == 23:
            return 0x190
        elif idx == 24:
            return 0x1a0
        elif idx == 25:
            return 0x1b0
        elif idx == 26:
            return 0x1c0
        elif idx == 27:
            return 0x1d0
        elif idx == 28:
            return 0x1e0
        elif idx == 29:
            return 0x1f0
        elif idx == 30:
            return 0x200
        elif idx == 31:
            return 0x210
        elif idx == 32:
            return 0x220
        elif idx == 33:
            return 0x230
        elif idx == 34:
            return 0x240
        elif idx == 35:
            return 0x250
        elif idx == 36:
            return 0x260
        elif idx == 37:
            return 0x270
        elif idx == 38:
            return 0x280
        elif idx == 39:
            return 0x290
        elif idx == 40:
            return 0x2a0
        elif idx == 41:
            return 0x2b0
        elif idx == 42:
            return 0x2c0
        elif idx == 43:
            return 0x2d0
        elif idx == 44:
            return 0x2e0
        elif idx == 45:
            return 0x2f0
        elif idx == 46:
            return 0x300
        elif idx == 47:
            return 0x310
        elif idx == 48:
            return 0x320
        elif idx == 49:
            return 0x330
        elif idx == 50:
            return 0x340
        elif idx == 51:
            return 0x350
        elif idx == 52:
            return 0x360
        elif idx == 53:
            return 0x370
        elif idx == 54:
            return 0x380
        elif idx == 55:
            return 0x390
        elif idx == 56:
            return 0x3a0
        elif idx == 57:
            return 0x3b0
        elif idx == 58:
            return 0x3c0
        elif idx == 59:
            return 0x3d0
        elif idx == 60:
            return 0x3e0
        elif idx == 61:
            return 0x3f0
        elif idx == 62:
            return 0x400
        elif idx == 63:
            return 0x410
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def tcache_bin_size(self, idx):
        """
        Convert an index in tcache bin array into a chunk size
        
        NB: On 64-bit, tidx2usize() actually has a difference of -8
        compared to the actual bin size (checked by looking at chunks in these bins). 
        We also checked the result of tidx2usize() in C language and is the same
        so we assume is normal and we just too add these +8...
           On 32-bit, I could not get a formula to match, so I just used an empiric formula...
        """
        # The below work but we my as well just list them for easier reading
        #if self.SIZE_SZ == 4:
        #    return (idx+1)*0x10 # hax, empiric
        #elif self.SIZE_SZ == 8:
        #    return self.tidx2usize(idx) + self.SIZE_SZ
        if self.SIZE_SZ == 4:
            return self.tcache_bin_size_32(idx)
        elif self.SIZE_SZ == 8:
            return self.tcache_bin_size_64(idx)

    def tcache_bin_index_32(self, size):
        """
        Convert a tcache chunk size into an index in tcache bin array (32-bit)
        """
        if size == 0x10:
            return 0
        elif size == 0x20:
            return 1
        elif size == 0x30:
            return 2
        elif size == 0x40:
            return 3
        elif size == 0x50:
            return 4
        elif size == 0x60:
            return 5
        elif size == 0x70:
            return 6
        elif size == 0x80:
            return 7
        elif size == 0x90:
            return 8
        elif size == 0xa0:
            return 9
        elif size == 0xb0:
            return 10
        elif size == 0xc0:
            return 11
        elif size == 0xd0:
            return 12
        elif size == 0xe0:
            return 13
        elif size == 0xf0:
            return 14
        elif size == 0x100:
            return 15
        elif size == 0x110:
            return 16
        elif size == 0x120:
            return 17
        elif size == 0x130:
            return 18
        elif size == 0x140:
            return 19
        elif size == 0x150:
            return 20
        elif size == 0x160:
            return 21
        elif size == 0x170:
            return 22
        elif size == 0x180:
            return 23
        elif size == 0x190:
            return 24
        elif size == 0x1a0:
            return 25
        elif size == 0x1b0:
            return 26
        elif size == 0x1c0:
            return 27
        elif size == 0x1d0:
            return 28
        elif size == 0x1e0:
            return 29
        elif size == 0x1f0:
            return 30
        elif size == 0x200:
            return 31
        elif size == 0x210:
            return 32
        elif size == 0x220:
            return 33
        elif size == 0x230:
            return 34
        elif size == 0x240:
            return 35
        elif size == 0x250:
            return 36
        elif size == 0x260:
            return 37
        elif size == 0x270:
            return 38
        elif size == 0x280:
            return 39
        elif size == 0x290:
            return 40
        elif size == 0x2a0:
            return 41
        elif size == 0x2b0:
            return 42
        elif size == 0x2c0:
            return 43
        elif size == 0x2d0:
            return 44
        elif size == 0x2e0:
            return 45
        elif size == 0x2f0:
            return 46
        elif size == 0x300:
            return 47
        elif size == 0x310:
            return 48
        elif size == 0x320:
            return 49
        elif size == 0x330:
            return 50
        elif size == 0x340:
            return 51
        elif size == 0x350:
            return 52
        elif size == 0x360:
            return 53
        elif size == 0x370:
            return 54
        elif size == 0x380:
            return 55
        elif size == 0x390:
            return 56
        elif size == 0x3a0:
            return 57
        elif size == 0x3b0:
            return 58
        elif size == 0x3c0:
            return 59
        elif size == 0x3d0:
            return 60
        elif size == 0x3e0:
            return 61
        elif size == 0x3f0:
            return 62
        elif size == 0x400:
            return 63
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def tcache_bin_index_64(self, size):
        """
        Convert a tcache chunk size into an index in tcache bin array (64-bit)
        """
        if size == 0x20:
            return 0
        elif size == 0x30:
            return 1
        elif size == 0x40:
            return 2
        elif size == 0x50:
            return 3
        elif size == 0x60:
            return 4
        elif size == 0x70:
            return 5
        elif size == 0x80:
            return 6
        elif size == 0x90:
            return 7
        elif size == 0xa0:
            return 8
        elif size == 0xb0:
            return 9
        elif size == 0xc0:
            return 10
        elif size == 0xd0:
            return 11
        elif size == 0xe0:
            return 12
        elif size == 0xf0:
            return 13
        elif size == 0x100:
            return 14
        elif size == 0x110:
            return 15
        elif size == 0x120:
            return 16
        elif size == 0x130:
            return 17
        elif size == 0x140:
            return 18
        elif size == 0x150:
            return 19
        elif size == 0x160:
            return 20
        elif size == 0x170:
            return 21
        elif size == 0x180:
            return 22
        elif size == 0x190:
            return 23
        elif size == 0x1a0:
            return 24
        elif size == 0x1b0:
            return 25
        elif size == 0x1c0:
            return 26
        elif size == 0x1d0:
            return 27
        elif size == 0x1e0:
            return 28
        elif size == 0x1f0:
            return 29
        elif size == 0x200:
            return 30
        elif size == 0x210:
            return 31
        elif size == 0x220:
            return 32
        elif size == 0x230:
            return 33
        elif size == 0x240:
            return 34
        elif size == 0x250:
            return 35
        elif size == 0x260:
            return 36
        elif size == 0x270:
            return 37
        elif size == 0x280:
            return 38
        elif size == 0x290:
            return 39
        elif size == 0x2a0:
            return 40
        elif size == 0x2b0:
            return 41
        elif size == 0x2c0:
            return 42
        elif size == 0x2d0:
            return 43
        elif size == 0x2e0:
            return 44
        elif size == 0x2f0:
            return 45
        elif size == 0x300:
            return 46
        elif size == 0x310:
            return 47
        elif size == 0x320:
            return 48
        elif size == 0x330:
            return 49
        elif size == 0x340:
            return 50
        elif size == 0x350:
            return 51
        elif size == 0x360:
            return 52
        elif size == 0x370:
            return 53
        elif size == 0x380:
            return 54
        elif size == 0x390:
            return 55
        elif size == 0x3a0:
            return 56
        elif size == 0x3b0:
            return 57
        elif size == 0x3c0:
            return 58
        elif size == 0x3d0:
            return 59
        elif size == 0x3e0:
            return 60
        elif size == 0x3f0:
            return 61
        elif size == 0x400:
            return 62
        elif size == 0x410:
            return 63
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def tcache_bin_index(self, size):
        """
        Convert a tcache chunk size into an index in tcache bin array

        NOTE: Python alternative to glibc csize2tidx() C macro.
        On 32-bit, I could not get the formula to match, and just noticed divinding by 2 works
        so was using that. We also checked the result of csize2tidx() in C language on 32-bit and is the same
        so we assume is normal and we just compute it ourselves too...
        """
        # index = int((size - self.MINSIZE + self.MALLOC_ALIGNMENT - 1) / self.MALLOC_ALIGNMENT)
        # if self.SIZE_SZ == 4:
        #     return index // 2 # hax, empiric
        # elif self.SIZE_SZ == 8:
        #     return index
        if self.SIZE_SZ == 4:
            return self.tcache_bin_index_32(size)
        elif self.SIZE_SZ == 8:
            return self.tcache_bin_index_64(size)

    #
    # fast bins
    #

    def fast_bin_size_32(self, idx):
        """
        Convert an index in fast bin array into a chunk size (32-bit)
        """
        if idx == 0:
            return 0x10
        elif idx == 1:
            return 0x18
        elif idx == 2:
            return 0x20
        elif idx == 3:
            return 0x28
        elif idx == 4:
            return 0x30
        elif idx == 5:
            return 0x38
        elif idx == 6:
            return 0x40
        elif idx == 7:
            return 0x48
        elif idx == 8:
            return 0x50
        elif idx == 9:
            return 0x58
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def fast_bin_size_64(self, idx):
        """
        Convert an index in fast bin array into a chunk size (64-bit)
        """
        if idx == 0:
            return 0x20
        elif idx == 1:
            return 0x30
        elif idx == 2:
            return 0x40
        elif idx == 3:
            return 0x50
        elif idx == 4:
            return 0x60
        elif idx == 5:
            return 0x70
        elif idx == 6:
            return 0x80
        elif idx == 7:
            return 0x90
        elif idx == 8:
            return 0xa0
        elif idx == 9:
            return 0xb0
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def fast_bin_size(self, idx):
        """
        Convert an index in fast bin array into a chunk size

        NOTE: below was en empiric computation that worked on 32-bit/64-bit
        but we prefer having the actual sizes in the code for easy lookup
        """
        # if self.SIZE_SZ == 4:
        #     return 0x10 + idx * 2 * self.SIZE_SZ
        # elif self.SIZE_SZ == 8:
        #     return 0x10 + idx * 0x10 + 2 * self.SIZE_SZ
        if self.SIZE_SZ == 4:
            return self.fast_bin_size_32(idx)
        elif self.SIZE_SZ == 8:
            return self.fast_bin_size_64(idx)

    def fast_bin_index_32(self, size):
        """
        Convert a fast chunk size into an index in fast bin array (32-bit)
        """
        if size == 0x10:
            return 0
        elif size == 0x18:
            return 1
        elif size == 0x20:
            return 2
        elif size == 0x28:
            return 3
        elif size == 0x30:
            return 4
        elif size == 0x38:
            return 5
        elif size == 0x40:
            return 6
        elif size == 0x48:
            return 7
        elif size == 0x50:
            return 8
        elif size == 0x58:
            return 9
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def fast_bin_index_64(self, size):
        """
        Convert a fast chunk size into an index in fast bin array (64-bit)
        """
        if size == 0x20:
            return 0
        elif size == 0x30:
            return 1
        elif size == 0x40:
            return 2
        elif size == 0x50:
            return 3
        elif size == 0x60:
            return 4
        elif size == 0x70:
            return 5
        elif size == 0x80:
            return 6
        elif size == 0x90:
            return 7
        elif size == 0xa0:
            return 8
        elif size == 0xb0:
            return 9
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def fast_bin_index(self, size):
        """
        Convert a fast chunk size into an index in fast bin array

        NOTE: There is a fastbin_index() C macro that works in Python too, but it is so much readable
        to have the actual chunk sizes in the code for easy lookup
        """
        # offset 2 to use otherwise unindexable first 2 bins
        # if self.SIZE_SZ == 4:
        #     return (size >> 3) - 2
        # elif self.SIZE_SZ == 8:
        #     return (size >> 4) - 2
        if self.SIZE_SZ == 4:
            return self.fast_bin_index_32(size)
        elif self.SIZE_SZ == 8:
            return self.fast_bin_index_64(size)

    #
    # small bins
    #

    def small_bin_size_32(self, idx):
        """
        Convert an index in small bin array into a chunk size (32-bit)
        """
        if idx == 1:
            return 0x10
        elif idx == 2:
            return 0x20
        elif idx == 3:
            return 0x30
        elif idx == 4:
            return 0x40
        elif idx == 5:
            return 0x50
        elif idx == 6:
            return 0x60
        elif idx == 7:
            return 0x70
        elif idx == 8:
            return 0x80
        elif idx == 9:
            return 0x90
        elif idx == 10:
            return 0xa0
        elif idx == 11:
            return 0xb0
        elif idx == 12:
            return 0xc0
        elif idx == 13:
            return 0xd0
        elif idx == 14:
            return 0xe0
        elif idx == 15:
            return 0xf0
        elif idx == 16:
            return 0x100
        elif idx == 17:
            return 0x110
        elif idx == 18:
            return 0x120
        elif idx == 19:
            return 0x130
        elif idx == 20:
            return 0x140
        elif idx == 21:
            return 0x150
        elif idx == 22:
            return 0x160
        elif idx == 23:
            return 0x170
        elif idx == 24:
            return 0x180
        elif idx == 25:
            return 0x190
        elif idx == 26:
            return 0x1a0
        elif idx == 27:
            return 0x1b0
        elif idx == 28:
            return 0x1c0
        elif idx == 29:
            return 0x1d0
        elif idx == 30:
            return 0x1e0
        elif idx == 31:
            return 0x1f0
        elif idx == 32:
            return 0x200
        elif idx == 33:
            return 0x210
        elif idx == 34:
            return 0x220
        elif idx == 35:
            return 0x230
        elif idx == 36:
            return 0x240
        elif idx == 37:
            return 0x250
        elif idx == 38:
            return 0x260
        elif idx == 39:
            return 0x270
        elif idx == 40:
            return 0x280
        elif idx == 41:
            return 0x290
        elif idx == 42:
            return 0x2a0
        elif idx == 43:
            return 0x2b0
        elif idx == 44:
            return 0x2c0
        elif idx == 45:
            return 0x2d0
        elif idx == 46:
            return 0x2e0
        elif idx == 47:
            return 0x2f0
        elif idx == 48:
            return 0x300
        elif idx == 49:
            return 0x310
        elif idx == 50:
            return 0x320
        elif idx == 51:
            return 0x330
        elif idx == 52:
            return 0x340
        elif idx == 53:
            return 0x350
        elif idx == 54:
            return 0x360
        elif idx == 55:
            return 0x370
        elif idx == 56:
            return 0x380
        elif idx == 57:
            return 0x390
        elif idx == 58:
            return 0x3a0
        elif idx == 59:
            return 0x3b0
        elif idx == 60:
            return 0x3c0
        elif idx == 61:
            return 0x3d0
        elif idx == 62:
            return 0x3e0
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def small_bin_size_64(self, idx):
        """
        Convert an index in small bin array into a chunk size (64-bit)
        """
        if idx == 1:
            return 0x20
        elif idx == 2:
            return 0x30
        elif idx == 3:
            return 0x40
        elif idx == 4:
            return 0x50
        elif idx == 5:
            return 0x60
        elif idx == 6:
            return 0x70
        elif idx == 7:
            return 0x80
        elif idx == 8:
            return 0x90
        elif idx == 9:
            return 0xa0
        elif idx == 10:
            return 0xb0
        elif idx == 11:
            return 0xc0
        elif idx == 12:
            return 0xd0
        elif idx == 13:
            return 0xe0
        elif idx == 14:
            return 0xf0
        elif idx == 15:
            return 0x100
        elif idx == 16:
            return 0x110
        elif idx == 17:
            return 0x120
        elif idx == 18:
            return 0x130
        elif idx == 19:
            return 0x140
        elif idx == 20:
            return 0x150
        elif idx == 21:
            return 0x160
        elif idx == 22:
            return 0x170
        elif idx == 23:
            return 0x180
        elif idx == 24:
            return 0x190
        elif idx == 25:
            return 0x1a0
        elif idx == 26:
            return 0x1b0
        elif idx == 27:
            return 0x1c0
        elif idx == 28:
            return 0x1d0
        elif idx == 29:
            return 0x1e0
        elif idx == 30:
            return 0x1f0
        elif idx == 31:
            return 0x200
        elif idx == 32:
            return 0x210
        elif idx == 33:
            return 0x220
        elif idx == 34:
            return 0x230
        elif idx == 35:
            return 0x240
        elif idx == 36:
            return 0x250
        elif idx == 37:
            return 0x260
        elif idx == 38:
            return 0x270
        elif idx == 39:
            return 0x280
        elif idx == 40:
            return 0x290
        elif idx == 41:
            return 0x2a0
        elif idx == 42:
            return 0x2b0
        elif idx == 43:
            return 0x2c0
        elif idx == 44:
            return 0x2d0
        elif idx == 45:
            return 0x2e0
        elif idx == 46:
            return 0x2f0
        elif idx == 47:
            return 0x300
        elif idx == 48:
            return 0x310
        elif idx == 49:
            return 0x320
        elif idx == 50:
            return 0x330
        elif idx == 51:
            return 0x340
        elif idx == 52:
            return 0x350
        elif idx == 53:
            return 0x360
        elif idx == 54:
            return 0x370
        elif idx == 55:
            return 0x380
        elif idx == 56:
            return 0x390
        elif idx == 57:
            return 0x3a0
        elif idx == 58:
            return 0x3b0
        elif idx == 59:
            return 0x3c0
        elif idx == 60:
            return 0x3d0
        elif idx == 61:
            return 0x3e0
        elif idx == 62:
            return 0x3f0
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def small_bin_size(self, idx):
        """
        Convert an index in small bin array into a chunk size
        
        NOTE: We tried to reverse the glibc smallbin_index() macro
        Not sure why but there was a difference of -16 (tested on 64-bit)
        compared to the actual bin size (checked by looking at chunks in these bins). 
        So we added self.INUSE_HDR_SZ assuming it was the right operation.
        But we don't use it anymore anyway as been replaced by smallbin_size_XX() calls
        """
        # if self.SMALLBIN_WIDTH == 16:
        #     return (idx << 4) + self.INUSE_HDR_SZ
        # else:
        #     #return (idx << 3) + self.INUSE_HDR_SZ
        #     return (idx << 4)
        if self.SIZE_SZ == 4:
            return self.small_bin_size_32(idx)
        elif self.SIZE_SZ == 8:
            return self.small_bin_size_64(idx)

    def small_bin_index_32(self, size):
        """
        Convert a small chunk size into an index in small bin array (32-bit)
        """
        if size <= 0x10:
            return 1
        elif size <= 0x20:
            return 2
        elif size <= 0x30:
            return 3
        elif size <= 0x40:
            return 4
        elif size <= 0x50:
            return 5
        elif size <= 0x60:
            return 6
        elif size <= 0x70:
            return 7
        elif size <= 0x80:
            return 8
        elif size <= 0x90:
            return 9
        elif size <= 0xa0:
            return 10
        elif size <= 0xb0:
            return 11
        elif size <= 0xc0:
            return 12
        elif size <= 0xd0:
            return 13
        elif size <= 0xe0:
            return 14
        elif size <= 0xf0:
            return 15
        elif size <= 0x100:
            return 16
        elif size <= 0x110:
            return 17
        elif size <= 0x120:
            return 18
        elif size <= 0x130:
            return 19
        elif size <= 0x140:
            return 20
        elif size <= 0x150:
            return 21
        elif size <= 0x160:
            return 22
        elif size <= 0x170:
            return 23
        elif size <= 0x180:
            return 24
        elif size <= 0x190:
            return 25
        elif size <= 0x1a0:
            return 26
        elif size <= 0x1b0:
            return 27
        elif size <= 0x1c0:
            return 28
        elif size <= 0x1d0:
            return 29
        elif size <= 0x1e0:
            return 30
        elif size <= 0x1f0:
            return 31
        elif size <= 0x200:
            return 32
        elif size <= 0x210:
            return 33
        elif size <= 0x220:
            return 34
        elif size <= 0x230:
            return 35
        elif size <= 0x240:
            return 36
        elif size <= 0x250:
            return 37
        elif size <= 0x260:
            return 38
        elif size <= 0x270:
            return 39
        elif size <= 0x280:
            return 40
        elif size <= 0x290:
            return 41
        elif size <= 0x2a0:
            return 42
        elif size <= 0x2b0:
            return 43
        elif size <= 0x2c0:
            return 44
        elif size <= 0x2d0:
            return 45
        elif size <= 0x2e0:
            return 46
        elif size <= 0x2f0:
            return 47
        elif size <= 0x300:
            return 48
        elif size <= 0x310:
            return 49
        elif size <= 0x320:
            return 50
        elif size <= 0x330:
            return 51
        elif size <= 0x340:
            return 52
        elif size <= 0x350:
            return 53
        elif size <= 0x360:
            return 54
        elif size <= 0x370:
            return 55
        elif size <= 0x380:
            return 56
        elif size <= 0x390:
            return 57
        elif size <= 0x3a0:
            return 58
        elif size <= 0x3b0:
            return 59
        elif size <= 0x3c0:
            return 60
        elif size <= 0x3d0:
            return 61
        elif size <= 0x3e0:
            return 62
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def small_bin_index_64(self, size):
        """
        Convert a small chunk size into an index in small bin array (64-bit)
        """
        if size <= 0x20:
            return 1
        elif size <= 0x30:
            return 2
        elif size <= 0x40:
            return 3
        elif size <= 0x50:
            return 4
        elif size <= 0x60:
            return 5
        elif size <= 0x70:
            return 6
        elif size <= 0x80:
            return 7
        elif size <= 0x90:
            return 8
        elif size <= 0xa0:
            return 9
        elif size <= 0xb0:
            return 10
        elif size <= 0xc0:
            return 11
        elif size <= 0xd0:
            return 12
        elif size <= 0xe0:
            return 13
        elif size <= 0xf0:
            return 14
        elif size <= 0x100:
            return 15
        elif size <= 0x110:
            return 16
        elif size <= 0x120:
            return 17
        elif size <= 0x130:
            return 18
        elif size <= 0x140:
            return 19
        elif size <= 0x150:
            return 20
        elif size <= 0x160:
            return 21
        elif size <= 0x170:
            return 22
        elif size <= 0x180:
            return 23
        elif size <= 0x190:
            return 24
        elif size <= 0x1a0:
            return 25
        elif size <= 0x1b0:
            return 26
        elif size <= 0x1c0:
            return 27
        elif size <= 0x1d0:
            return 28
        elif size <= 0x1e0:
            return 29
        elif size <= 0x1f0:
            return 30
        elif size <= 0x200:
            return 31
        elif size <= 0x210:
            return 32
        elif size <= 0x220:
            return 33
        elif size <= 0x230:
            return 34
        elif size <= 0x240:
            return 35
        elif size <= 0x250:
            return 36
        elif size <= 0x260:
            return 37
        elif size <= 0x270:
            return 38
        elif size <= 0x280:
            return 39
        elif size <= 0x290:
            return 40
        elif size <= 0x2a0:
            return 41
        elif size <= 0x2b0:
            return 42
        elif size <= 0x2c0:
            return 43
        elif size <= 0x2d0:
            return 44
        elif size <= 0x2e0:
            return 45
        elif size <= 0x2f0:
            return 46
        elif size <= 0x300:
            return 47
        elif size <= 0x310:
            return 48
        elif size <= 0x320:
            return 49
        elif size <= 0x330:
            return 50
        elif size <= 0x340:
            return 51
        elif size <= 0x350:
            return 52
        elif size <= 0x360:
            return 53
        elif size <= 0x370:
            return 54
        elif size <= 0x380:
            return 55
        elif size <= 0x390:
            return 56
        elif size <= 0x3a0:
            return 57
        elif size <= 0x3b0:
            return 58
        elif size <= 0x3c0:
            return 59
        elif size <= 0x3d0:
            return 60
        elif size <= 0x3e0:
            return 61
        elif size <= 0x3f0:
            return 62
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def small_bin_index(self, size):
        """
        Convert a small chunk size into an index in small bin array

        NOTE: We previously used a Python implementation of the smallbin_index() C macro
        but not sure if the below was correct. We prefer to use the actual
        sizes for easy lookup anyway
        """
        # if self.SMALLBIN_WIDTH == 16:
        #     return size >> 4
        # else:
        #     return (size >> 3) + self.SMALLBIN_CORRECTION
        if self.SIZE_SZ == 4:
            return self.small_bin_index_32(size)
        elif self.SIZE_SZ == 8:
            return self.small_bin_index_64(size)

    #
    # large bins
    #

    def large_bin_size_32(self, idx):
        """
        Convert an index in large bin array into a chunk size (32-bit)
        """
        if idx == 63:
            return 0x3f0
        elif idx == 64:
            return 0x430
        elif idx == 65:
            return 0x470
        elif idx == 66:
            return 0x4b0
        elif idx == 67:
            return 0x4f0
        elif idx == 68:
            return 0x530
        elif idx == 69:
            return 0x570
        elif idx == 70:
            return 0x5b0
        elif idx == 71:
            return 0x5f0
        elif idx == 72:
            return 0x630
        elif idx == 73:
            return 0x670
        elif idx == 74:
            return 0x6b0
        elif idx == 75:
            return 0x6f0
        elif idx == 76:
            return 0x730
        elif idx == 77:
            return 0x770
        elif idx == 78:
            return 0x7b0
        elif idx == 79:
            return 0x7f0
        elif idx == 80:
            return 0x830
        elif idx == 81:
            return 0x870
        elif idx == 82:
            return 0x8b0
        elif idx == 83:
            return 0x8f0
        elif idx == 84:
            return 0x930
        elif idx == 85:
            return 0x970
        elif idx == 86:
            return 0x9b0
        elif idx == 87:
            return 0x9f0
        elif idx == 88:
            return 0xa30
        elif idx == 89:
            return 0xa70
        elif idx == 90:
            return 0xab0
        elif idx == 91:
            return 0xaf0
        elif idx == 92:
            return 0xb30
        elif idx == 93:
            return 0xb70
        elif idx == 94:
            return 0xbb0
        elif idx == 95:
            return 0xbf0
        elif idx == 96:
            return 0xdf0
        elif idx == 97:
            return 0xff0
        elif idx == 98:
            return 0x11f0
        elif idx == 99:
            return 0x13f0
        elif idx == 100:
            return 0x15f0
        elif idx == 101:
            return 0x17f0
        elif idx == 102:
            return 0x19f0
        elif idx == 103:
            return 0x1bf0
        elif idx == 104:
            return 0x1df0
        elif idx == 105:
            return 0x1ff0
        elif idx == 106:
            return 0x21f0
        elif idx == 107:
            return 0x23f0
        elif idx == 108:
            return 0x25f0
        elif idx == 109:
            return 0x27f0
        elif idx == 110:
            return 0x29f0
        elif idx == 111:
            return 0x2ff0
        elif idx == 112:
            return 0x3ff0
        elif idx == 113:
            return 0x4ff0
        elif idx == 114:
            return 0x5ff0
        elif idx == 115:
            return 0x6ff0
        elif idx == 116:
            return 0x7ff0
        elif idx == 117:
            return 0x8ff0
        elif idx == 118:
            return 0x9ff0
        elif idx == 119:
            return 0xfff0
        elif idx == 120:
            return 0x17ff0
        elif idx == 121:
            return 0x1fff0
        elif idx == 122:
            return 0x27ff0
        elif idx == 123:
            return 0x67ff0
        elif idx == 124:
            return 0xa7ff0
        elif idx == 125:
            return 0xe7ff0
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def large_bin_size_64(self, idx):
        """
        Convert an index in large bin array into a chunk size (64-bit)
        """
        if idx == 63:
            return 0x430
        elif idx == 64:
            return 0x470
        elif idx == 65:
            return 0x4b0
        elif idx == 66:
            return 0x4f0
        elif idx == 67:
            return 0x530
        elif idx == 68:
            return 0x570
        elif idx == 69:
            return 0x5b0
        elif idx == 70:
            return 0x5f0
        elif idx == 71:
            return 0x630
        elif idx == 72:
            return 0x670
        elif idx == 73:
            return 0x6b0
        elif idx == 74:
            return 0x6f0
        elif idx == 75:
            return 0x730
        elif idx == 76:
            return 0x770
        elif idx == 77:
            return 0x7b0
        elif idx == 78:
            return 0x7f0
        elif idx == 79:
            return 0x830
        elif idx == 80:
            return 0x870
        elif idx == 81:
            return 0x8b0
        elif idx == 82:
            return 0x8f0
        elif idx == 83:
            return 0x930
        elif idx == 84:
            return 0x970
        elif idx == 85:
            return 0x9b0
        elif idx == 86:
            return 0x9f0
        elif idx == 87:
            return 0xa30
        elif idx == 88:
            return 0xa70
        elif idx == 89:
            return 0xab0
        elif idx == 90:
            return 0xaf0
        elif idx == 91:
            return 0xb30
        elif idx == 92:
            return 0xb70
        elif idx == 93:
            return 0xbb0
        elif idx == 94:
            return 0xbf0
        elif idx == 95:
            return 0xc30
        elif idx == 96:
            return 0xdf0
        elif idx == 97:
            return 0xff0
        elif idx == 98:
            return 0x11f0
        elif idx == 99:
            return 0x13f0
        elif idx == 100:
            return 0x15f0
        elif idx == 101:
            return 0x17f0
        elif idx == 102:
            return 0x19f0
        elif idx == 103:
            return 0x1bf0
        elif idx == 104:
            return 0x1df0
        elif idx == 105:
            return 0x1ff0
        elif idx == 106:
            return 0x21f0
        elif idx == 107:
            return 0x23f0
        elif idx == 108:
            return 0x25f0
        elif idx == 109:
            return 0x27f0
        elif idx == 110:
            return 0x29f0
        elif idx == 111:
            return 0x2ff0
        elif idx == 112:
            return 0x3ff0
        elif idx == 113:
            return 0x4ff0
        elif idx == 114:
            return 0x5ff0
        elif idx == 115:
            return 0x6ff0
        elif idx == 116:
            return 0x7ff0
        elif idx == 117:
            return 0x8ff0
        elif idx == 118:
            return 0x9ff0
        elif idx == 119:
            return 0xfff0
        elif idx == 120:
            return 0x17ff0
        elif idx == 121:
            return 0x1fff0
        elif idx == 122:
            return 0x27ff0
        elif idx == 123:
            return 0x67ff0
        elif idx == 124:
            return 0xa7ff0
        elif idx == 125:
            return 0xe7ff0
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def large_bin_size(self, index):
        """
        Convert an index in large bin array into a chunk size
        """
        if self.SIZE_SZ == 4:
            return self.large_bin_size_32(index)
        elif self.SIZE_SZ == 8:
            return self.large_bin_size_64(index)

    def large_bin_index_32(self, size):
        """
        Convert a large chunk size into an index in large bin array (32-bit)

        NOTE: the below code mimic-ing the largebin_index_32() C macro does not
        give us chunks' sizes found empirically so we do it differently...
        """
        # if (size >> 6) <= 38:
        #     return 56 + (size >> 6)
        # elif (size >> 9) <= 20:
        #     return 91 + (size >> 9)
        # elif (size >> 12) <= 10:
        #     return 110 + (size >> 12)
        # elif (size >> 15) <= 4:
        #     return 119 + (size >> 15)
        # elif (size >> 18) <= 2:
        #     return 124 + (size >> 18)
        # else:
        #     return 126
        if size <= 0x3f0:
            return 63
        elif size <= 0x430:
            return 64
        elif size <= 0x470:
            return 65
        elif size <= 0x4b0:
            return 66
        elif size <= 0x4f0:
            return 67
        elif size <= 0x530:
            return 68
        elif size <= 0x570:
            return 69
        elif size <= 0x5b0:
            return 70
        elif size <= 0x5f0:
            return 71
        elif size <= 0x630:
            return 72
        elif size <= 0x670:
            return 73
        elif size <= 0x6b0:
            return 74
        elif size <= 0x6f0:
            return 75
        elif size <= 0x730:
            return 76
        elif size <= 0x770:
            return 77
        elif size <= 0x7b0:
            return 78
        elif size <= 0x7f0:
            return 79
        elif size <= 0x830:
            return 80
        elif size <= 0x870:
            return 81
        elif size <= 0x8b0:
            return 82
        elif size <= 0x8f0:
            return 83
        elif size <= 0x930:
            return 84
        elif size <= 0x970:
            return 85
        elif size <= 0x9b0:
            return 86
        elif size <= 0x9f0:
            return 87
        elif size <= 0xa30:
            return 88
        elif size <= 0xa70:
            return 89
        elif size <= 0xab0:
            return 90
        elif size <= 0xaf0:
            return 91
        elif size <= 0xb30:
            return 92
        elif size <= 0xb70:
            return 93
        elif size <= 0xbb0:
            return 94
        elif size <= 0xbf0:
            return 95
        elif size <= 0xdf0:
            return 96
        elif size <= 0xff0:
            return 97
        elif size <= 0x11f0:
            return 98
        elif size <= 0x13f0:
            return 99
        elif size <= 0x15f0:
            return 100
        elif size <= 0x17f0:
            return 101
        elif size <= 0x19f0:
            return 102
        elif size <= 0x1bf0:
            return 103
        elif size <= 0x1df0:
            return 104
        elif size <= 0x1ff0:
            return 105
        elif size <= 0x21f0:
            return 106
        elif size <= 0x23f0:
            return 107
        elif size <= 0x25f0:
            return 108
        elif size <= 0x27f0:
            return 109
        elif size <= 0x29f0:
            return 110
        elif size <= 0x2ff0:
            return 111
        elif size <= 0x3ff0:
            return 112
        elif size <= 0x4ff0:
            return 113
        elif size <= 0x5ff0:
            return 114
        elif size <= 0x6ff0:
            return 115
        elif size <= 0x7ff0:
            return 116
        elif size <= 0x8ff0:
            return 117
        elif size <= 0x9ff0:
            return 118
        elif size <= 0xfff0:
            return 119
        elif size <= 0x17ff0:
            return 120
        elif size <= 0x1fff0:
            return 121
        elif size <= 0x27ff0:
            return 122
        elif size <= 0x67ff0:
            return 123
        elif size <= 0xa7ff0:
            return 124
        elif size <= 0xe7ff0:
            return 125
        else:
            return 126

    def large_bin_index_64(self, sz):
        """
        Convert a large chunk size into an index in large bin array (64-bit)

        NOTE: the below code mimic-ing the largebin_index_64() C macro does not
        give us chunks' sizes found empirically so we do it differently...
        """
        # if (sz >> 6) <= 48:
        #     return 48 + (sz >> 6)
        # elif (sz >> 9) <= 20:
        #     return 91 + (sz >> 9)
        # elif (sz >> 12) <= 10:
        #     return 110 + (sz >> 12)
        # elif (sz >> 15) <= 4:
        #     return 119 + (sz >> 15)
        # elif (sz >> 18) <= 2:
        #     return 124 + (sz >> 18)
        # else:
        #     return 126
        if size <= 0x430:
            return 63
        elif size <= 0x470:
            return 64
        elif size <= 0x4b0:
            return 65
        elif size <= 0x4f0:
            return 66
        elif size <= 0x530:
            return 67
        elif size <= 0x570:
            return 68
        elif size <= 0x5b0:
            return 69
        elif size <= 0x5f0:
            return 70
        elif size <= 0x630:
            return 71
        elif size <= 0x670:
            return 72
        elif size <= 0x6b0:
            return 73
        elif size <= 0x6f0:
            return 74
        elif size <= 0x730:
            return 75
        elif size <= 0x770:
            return 76
        elif size <= 0x7b0:
            return 77
        elif size <= 0x7f0:
            return 78
        elif size <= 0x830:
            return 79
        elif size <= 0x870:
            return 80
        elif size <= 0x8b0:
            return 81
        elif size <= 0x8f0:
            return 82
        elif size <= 0x930:
            return 83
        elif size <= 0x970:
            return 84
        elif size <= 0x9b0:
            return 85
        elif size <= 0x9f0:
            return 86
        elif size <= 0xa30:
            return 87
        elif size <= 0xa70:
            return 88
        elif size <= 0xab0:
            return 89
        elif size <= 0xaf0:
            return 90
        elif size <= 0xb30:
            return 91
        elif size <= 0xb70:
            return 92
        elif size <= 0xbb0:
            return 93
        elif size <= 0xbf0:
            return 94
        elif size <= 0xc30:
            return 95
        elif size <= 0xdf0:
            return 96
        elif size <= 0xff0:
            return 97
        elif size <= 0x11f0:
            return 98
        elif size <= 0x13f0:
            return 99
        elif size <= 0x15f0:
            return 100
        elif size <= 0x17f0:
            return 101
        elif size <= 0x19f0:
            return 102
        elif size <= 0x1bf0:
            return 103
        elif size <= 0x1df0:
            return 104
        elif size <= 0x1ff0:
            return 105
        elif size <= 0x21f0:
            return 106
        elif size <= 0x23f0:
            return 107
        elif size <= 0x25f0:
            return 108
        elif size <= 0x27f0:
            return 109
        elif size <= 0x29f0:
            return 110
        elif size <= 0x2ff0:
            return 111
        elif size <= 0x3ff0:
            return 112
        elif size <= 0x4ff0:
            return 113
        elif size <= 0x5ff0:
            return 114
        elif size <= 0x6ff0:
            return 115
        elif size <= 0x7ff0:
            return 116
        elif size <= 0x8ff0:
            return 117
        elif size <= 0x9ff0:
            return 118
        elif size <= 0xfff0:
            return 119
        elif size <= 0x17ff0:
            return 120
        elif size <= 0x1fff0:
            return 121
        elif size <= 0x27ff0:
            return 122
        elif size <= 0x67ff0:
            return 123
        elif size <= 0xa7ff0:
            return 124
        elif size <= 0xe7ff0:
            return 125
        else:
            return 126

    def large_bin_index(self, sz):
        """
        Convert a large chunk size into an index in large bin array
        
        NOTE: Closed to largebin_index() C macro but working on actual chunks sizes
        found empirically
        """
        if self.SIZE_SZ == 4:
            return self.large_bin_index_32(sz)

        elif self.SIZE_SZ == 8:
            return self.large_bin_index_64(sz)

    #
    # all regular bins
    #

    def bin_size(self, index):
        """Comment in malloc.c is not precise and misleading:
        ```
        Indexing

            Bins for sizes < 512 bytes contain chunks of all the same size, spaced
            8 bytes apart. Larger bins are approximately logarithmically spaced:

            64 bins of size       8
            32 bins of size      64
            16 bins of size     512
            8 bins of size    4096
            4 bins of size   32768
            2 bins of size  262144
            1 bin  of size what's left
        ```
            
        We didn't noticed that empirically. So instead we wrote our own implementation
        that works empirically.
        """

        if index == self.bin_index_unsorted:
            return None # Unsorted bin does not have a size
        elif index <= self.bin_index_small_max:
            return self.small_bin_size(index)
        elif index <= self.bin_index_large_max:
            return self.large_bin_size(index)
        elif index == self.bin_index_uncategorized:
            return None
        else:
            pu.print_error("Unsupported, should not happen")
            raise Exception("sys.exit()")

    def bin_index(self, sz):
        "return the bin index"

        if self.in_smallbin_range(sz):
            return self.small_bin_index(sz)
        else:
            return self.large_bin_index(sz)
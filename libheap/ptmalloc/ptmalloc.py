import struct
import sys

from libheap.frontend.printutils import print_error
from libheap.ptmalloc.malloc_chunk import malloc_chunk


class ptmalloc:
    def __init__(self, SIZE_SZ=None, debugger=None):

        self.terse = True  # XXX - This should be configurable
        self.SIZE_SZ = SIZE_SZ

        self.NBINS = 128
        self.NSMALLBINS = 64
        self.BINMAPSHIFT = 5
        self.FASTCHUNKS_BIT = 0x1
        self.NONCONTIGUOUS_BIT = 0x2
        self.HEAP_MIN_SIZE = 32 * 1024
        self.HEAP_MAX_SIZE = 1024 * 1024
        self.BITSPERMAP = 1 << self.BINMAPSHIFT
        self.BINMAPSIZE = self.NBINS / self.BITSPERMAP

        self.PREV_INUSE = 1
        self.IS_MMAPPED = 2
        self.NON_MAIN_ARENA = 4
        self.SIZE_BITS = self.PREV_INUSE | self.IS_MMAPPED | self.NON_MAIN_ARENA

        self.ptchunk_callback = None
        self.ptchunk_callback_cached = None
        # Assume we can re-use known mstate when not specified
        self.pt_cached_mstate = None
        self.arena_address = None

        self.ar_ptr = None
        self.mp = None

        self.dbg = debugger
        self.set_globals(SIZE_SZ=self.SIZE_SZ)
        if debugger is not None:
            self.inferior = debugger.get_inferior()
        else:
            self.inferior = None

    def set_globals(self, SIZE_SZ=None):
        if SIZE_SZ is None:
            if self.dbg is None:
                print_error("Please specify a SIZE_SZ value or run in debugger.")
                raise Exception("sys.exit()")

            self.SIZE_SZ = self.dbg.get_size_sz()
            if self.SIZE_SZ is None:
                print_error("error fetching size")
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
        self.MIN_LARGE_SIZE = self.NSMALLBINS * self.SMALLBIN_WIDTH

        self.MAX_FAST_SIZE = 80 * self.SIZE_SZ / 4
        size = self.request2size(self.MAX_FAST_SIZE)
        self.NFASTBINS = self.fastbin_index(size) + 1

        self.INUSE_HDR_SZ = 2 * self.SIZE_SZ
        self.FREE_FASTCHUNK_HDR_SZ = 3 * self.SIZE_SZ
        self.FREE_HDR_SZ = 4 * self.SIZE_SZ
        self.FREE_LARGE_HDR_SZ = 6 * self.SIZE_SZ

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

    def fastbin(self, ar_ptr, idx):
        return ar_ptr.fastbinsY[idx]

    def fastbin_index(self, sz):
        "offset 2 to use otherwise unindexable first 2 bins"
        if self.SIZE_SZ == 8:
            return (sz >> 4) - 2
        elif self.SIZE_SZ == 4:
            return (sz >> 3) - 2

    def top(self, ar_ptr):
        return ar_ptr.top

    def heap_for_ptr(self, ptr):
        "find the heap and corresponding arena for a given ptr"
        return ptr & ~(self.HEAP_MAX_SIZE - 1)

    def chunksize(self, p):
        "Get size, ignoring use bits"
        return p.size & ~self.SIZE_BITS

    def mutex_lock(self, ar_ptr):
        ar_ptr.mutex = 1
        try:
            self.dbg.write_memory(ar_ptr.address, struct.pack("<I", ar_ptr.mutex))
        except:
            # write_memory does not work on core dumps, but we also don't need
            # to lock the mutex there
            pass

    def mutex_unlock(self, ar_ptr):
        ar_ptr.mutex = 0
        try:
            self.dbg.write_memory(ar_ptr.address, struct.pack("<I", ar_ptr.mutex))
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
        return malloc_chunk(self, p.address + s, inuse=False, debugger=self.dbg)

    def inuse(self, p):
        "extract p's inuse bit"
        return (
            malloc_chunk(
                self,
                addr=p.address + (p.size & ~self.SIZE_BITS),
                inuse=False,
                debugger=self.dbg,
            ).size
            & self.PREV_INUSE
        )

    def set_inuse(self, p):
        "set chunk as being inuse without otherwise disturbing"
        chunk = malloc_chunk(
            self,
            (p.address + (p.size & ~self.SIZE_BITS)),
            inuse=False,
            debugger=self.dbg,
        )
        chunk.size |= self.PREV_INUSE
        chunk.write()

    def clear_inuse(self, p):
        "clear chunk as being inuse without otherwise disturbing"
        chunk = malloc_chunk(
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
            malloc_chunk(
                self, addr=(p.address + s), inuse=False, debugger=self.dbg
            ).size
            & self.PREV_INUSE
        )

    def set_inuse_bit_at_offset(self, p, s):
        "set inuse bits in known places"
        chunk = malloc_chunk(self, addr=(p.address + s), inuse=False, debugger=self.dbg)
        chunk.size |= self.PREV_INUSE
        chunk.write()

    def clear_inuse_bit_at_offset(self, p, s):
        "clear inuse bits in known places"
        chunk = malloc_chunk(self, addr=(p.address + s), inuse=False, debugger=self.dbg)
        chunk.size &= ~self.PREV_INUSE
        chunk.write()

    def bin_at(self, m, i):
        "addressing -- note that bin_at(0) does not exist"

        if i == 0:
            print_error("bin_at(0) does not exist")
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

    def in_smallbin_range(self, sz):
        "check if size is in smallbin range"
        return sz < self.MIN_LARGE_SIZE

    def smallbin_index(self, sz):
        "return the smallbin index"

        if self.SMALLBIN_WIDTH == 16:
            return sz >> 4
        else:
            return sz >> 3

    def largebin_index_32(self, sz):
        "return the 32bit largebin index"

        if (sz >> 6) <= 38:
            return 56 + (sz >> 6)
        elif (sz >> 9) <= 20:
            return 91 + (sz >> 9)
        elif (sz >> 12) <= 10:
            return 110 + (sz >> 12)
        elif (sz >> 15) <= 4:
            return 119 + (sz >> 15)
        elif (sz >> 18) <= 2:
            return 124 + (sz >> 18)
        else:
            return 126

    def largebin_index_64(self, sz):
        "return the 64bit largebin index"

        if (sz >> 6) <= 48:
            return 48 + (sz >> 6)
        elif (sz >> 9) <= 20:
            return 91 + (sz >> 9)
        elif (sz >> 12) <= 10:
            return 110 + (sz >> 12)
        elif (sz >> 15) <= 4:
            return 119 + (sz >> 15)
        elif (sz >> 18) <= 2:
            return 124 + (sz >> 18)
        else:
            return 126

    def largebin_index(self, sz):
        "return the largebin index"

        if self.SIZE_SZ == 8:
            return self.largebin_index_64(sz)
        elif self.SIZE_SZ == 4:
            return self.largebin_index_32(sz)

    def bin_index(self, sz):
        "return the bin index"

        if self.in_smallbin_range(sz):
            return self.smallbin_index(sz)
        else:
            return self.largebin_index(sz)

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

    def chunk_info(self, p, inuse_override=None):
        info = []
        info.append("0x%lx " % p.address)
        if p.fastchunk_freed is True:
            info.append("f ")
        elif self.inuse(p):
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

        info.append("\b")
        return "".join(info)

    # XXX - maybe move into helpers or something
    def print_hexdump(self, p, maxlen=0, off=0, verbose=False):
        data = self.ptr_from_ptmalloc_chunk(p) + off
        size = self.chunksize(p) - p.hdr_size - off
        print("0x%x bytes of chunk data:" % size)
        if size <= 0:
            if p.inuse:
                print("[!] Chunk corrupt? Bad size")
                return
            else:
                if verbose:
                    print("<old chunk contents merged with free header>")
                return
        if maxlen != 0:
            if size > maxlen:
                size = maxlen
        # XXX - should make hex cmds debugger agnostic
        if self.SIZE_SZ == 4:
            cmd = "x/%dwx 0x%x\n" % (size / 4, data)
        elif self.SIZE_SZ == 8:
            cmd = "x/%dwx 0x%x\n" % (size / 4, data)
            # cmd = "x/%dgx 0x%x\n" % (size/8, data)
            # cmd = "dps 0x%x %d\n" % (data, size/8)
        print(self.dbg.execute(cmd, True))
        return

    # XXX - maybe move into some debugger helper?
    def search_chunk(self, p, search_for, width, depth=0, skip=False):
        "searches a chunk. includes the chunk header in the search"

        if depth == 0 or depth > self.chunksize(p):
            depth = self.chunksize(p)

        start_address = p.address
        if skip:
            start_address += p.hdr_size
        try:
            result = self.dbg.search(
                start_address, p.address + depth, search_for, width
            )
        except Exception:
            # print(sys.exc_info()[0])
            # print("[libptmalloc] failed to execute 'find'")
            return False

        str_results = result.split("\n")

        for str_result in str_results:
            if str_result.startswith("0x"):
                return True

        return False

    def ptr_from_ptmalloc_chunk(self, p):
        return p.address + (self.SIZE_SZ * 2)

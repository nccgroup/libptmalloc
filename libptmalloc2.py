# libptmalloc2.py
#
# This file is part of libptmalloc.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# This is a library designed for analysis of libptmalloc2. It is heavily based
# on libheap.py by cloudburst.(https://github.com/cloudburst/libheap). In
# addition to new functionality, it has been modified to more closely model
# commands available in other tools like libdlmalloc and libtalloc
#
# Some gdb argument handling functions were taken and/or inspired from
# https://github.com/0vercl0k/stuffz/blob/master/dps_like_for_gdb.py
#
# Conventions:
# - Everything not in pt_helper should be prefixed by pt* to avoid conflicts
#   with other libs
# - More specifically, all structures should be name pt_* (such as pt_chunk)
#   whereas gdb cmds should be name pt* (without underscore, such as ptchunk)
# - Everything else should be stored in pt_helper and NOT be prefixed with pt*
#
from __future__ import print_function

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    exit()

import os
from os.path import basename

import importlib, binascii
import sys
import struct
import traceback
from functools import wraps
try:
    from printutils import *
    from prettyprinters import *
except Exception:
    # XXX - find a way to actually import the ones from libptmalloc in case 
    # we modify these files
    print("[libptmalloc] Run 'python setup.py install' to use printers")
    sys.exit(1)

import helper_gdb as hgdb
importlib.reload(hgdb)
import helper as h
importlib.reload(h)

class logger:
    def logmsg(self, s, end=None):
        if type(s) == str:
            if end != None:
                print("[libptmalloc] " + s, end=end)
            else:
                print("[libptmalloc] " + s)
        else:
            print(s)

################################################################################
# HELPERS
################################################################################

def gdb_backtrace(f):
    "decorator to let us show proper stack traces"

    @wraps(f)
    def catch_exceptions(*args, **kwargs):
        try:
            f(*args, **kwargs)
        except Exception:
            h.show_last_exception()

def read_proc_maps(pid):
    '''
    Locate the stack of a process using /proc/pid/maps.
    Will not work on hardened machines (grsec).
    '''

    filename = '/proc/%d/maps' % pid

    try:
        fd = open(filename)
    except IOError:
        print_error("Unable to open {0}".format(filename))
        return -1,-1

    found = libc_begin = libc_end = heap_begin = heap_end = 0
    for line in fd:
        if line.find("libc-") != -1:
            fields = line.split()

            libc_begin,libc_end = fields[0].split('-')
            libc_begin = int(libc_begin,16)
            libc_end = int(libc_end,16)
        elif line.find("heap") != -1:
            fields = line.split()

            heap_begin,heap_end= fields[0].split('-')
            heap_begin = int(heap_begin,16)
            heap_end = int(heap_end,16)

    fd.close()

    if libc_begin==0 or libc_end==0:
        print_error("Unable to read libc address information via /proc")
        return -1,-1

    if heap_begin==0 or heap_end==0:
        print_error("Unable to read heap address information via /proc")
        return -1,-1

    return libc_end,heap_begin

# General class for all helper methods to avoid namespace overlap with other
# heap libraries
class pt_helper():

    PREV_INUSE     = 1
    IS_MMAPPED     = 2
    NON_MAIN_ARENA = 4
    SIZE_BITS      = (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)    

    NBINS          = 128
    NSMALLBINS     = 64

    BINMAPSHIFT = 5
    BITSPERMAP  = 1 << BINMAPSHIFT
    BINMAPSIZE  = (NBINS / BITSPERMAP)

    FASTCHUNKS_BIT = 0x1

    NONCONTIGUOUS_BIT = 0x2

    HEAP_MIN_SIZE     = 32 * 1024
    HEAP_MAX_SIZE     = 1024 * 1024

    def __init__(self):
        self.terse = True # XXX - This should be configurable
        self.retrieve_sizesz()
        self.ptchunk_callback = None
        self.ptchunk_callback_cached = None
        # Assume we can re-use known mstate when not specified
        self.pt_cached_mstate = None
        self.arena_address = None

    def logmsg(self, s, end=None):
        if type(s) == str:
            if end != None:
                print("[libptmalloc] " + s, end=end)
            else:
                print("[libptmalloc] " + s)
        else:
            print(s)

    def retrieve_sizesz(self):
        """Retrieve the SIZE_SZ after binary loading finished,
           this allows import within .gdbinit"""

        _machine = self.get_arch()
        if "elf64" in _machine:
            self.SIZE_SZ = 8
        elif "elf32" in _machine:
            self.SIZE_SZ = 4
        else:
            raise Exception("Retrieving the SIZE_SZ failed.")

        self.INUSE_HDR_SZ      = 2 * self.SIZE_SZ
        self.FREE_FASTCHUNK_HDR_SZ = 3 * self.SIZE_SZ
        self.FREE_HDR_SZ       = 4 * self.SIZE_SZ
        self.FREE_LARGE_HDR_SZ = 6 * self.SIZE_SZ

        self.MIN_CHUNK_SIZE    = 4 * self.SIZE_SZ
        self.MALLOC_ALIGNMENT  = 2 * self.SIZE_SZ
        self.MALLOC_ALIGN_MASK = self.MALLOC_ALIGNMENT - 1
        self.MINSIZE           = (self.MIN_CHUNK_SIZE+self.MALLOC_ALIGN_MASK) & ~self.MALLOC_ALIGN_MASK

        self.SMALLBIN_WIDTH = self.MALLOC_ALIGNMENT
        self.MIN_LARGE_SIZE = (self.NSMALLBINS * self.SMALLBIN_WIDTH)

        self.MAX_FAST_SIZE = (80 * self.SIZE_SZ / 4)
        self.NFASTBINS     = (self.fastbin_index(self.request2size(self.MAX_FAST_SIZE)) + 1)

    # This can be initialized to register a callback that will dump additional
    # embedded information while analyzing a ptmalloc chunk. An example (and why
    # this was written) is the Cisco ASA mh header.
    # XXX - Would be nice if the callback implemented a test call to see that we
    # can actually run it before we say it's there. :)
    def register_callback(self, func):
        self.ptchunk_callback = func
        self.logmsg("Registered new ptchunk callback")

    def get_arch(self):
        res = gdb.execute("maintenance info sections ?", to_string=True)
        if "elf32-i386" in res and "elf64-x86-64" in res:
            raise("get_arch: could not determine arch (1)")
        if "elf32-i386" not in res and "elf64-x86-64" not in res:
            raise("get_arch: could not determine arch (2)")
        if "elf32-i386" in res:
            return "elf32-i386"
        elif "elf64-x86-64" in res:
            return "elf64-x86-64"
        else:
            raise("get_arch: failed to find arch")

    def chunk2mem(self, p):
        "conversion from malloc header to user pointer"
        return (p.address + (2*self.SIZE_SZ))

    def mem2chunk(self, mem):
        "conversion from user pointer to malloc header"
        return (mem - (2*self.SIZE_SZ))

    def request2size(self, req):
        "pad request bytes into a usable size"

        if (req + self.SIZE_SZ + self.MALLOC_ALIGN_MASK < self.MINSIZE):
            return self.MINSIZE
        else:
            return (int(req + self.SIZE_SZ + self.MALLOC_ALIGN_MASK) & \
                    ~self.MALLOC_ALIGN_MASK)

    def prev_inuse(self, p):
        "extract inuse bit of previous chunk"
        return (p.size & self.PREV_INUSE)

    def chunk_is_mmapped(self, p):
        "check for mmap()'ed chunk"
        return (p.size & self.IS_MMAPPED)

    def chunk_non_main_arena(self, p):
        "check for chunk from non-main arena"
        return (p.size & self.NON_MAIN_ARENA)

    def chunksize(self, p):
        "Get size, ignoring use bits"
        return (p.size & ~self.SIZE_BITS)

    def ptr_from_ptmalloc_chunk(self, p):
        return (p.address + (self.SIZE_SZ * 2))

    def next_chunk(self, p):
        "Ptr to next physical malloc_chunk."
        return (p.address + (p.size & ~self.SIZE_BITS))

    def prev_chunk(self, p):
        "Ptr to previous physical malloc_chunk"
        return (p.address - p.prev_size)

    def chunk_at_offset(self, p, s):
        "Treat space at ptr + offset as a chunk"
        return pt_chunk(self, p.address + s, inuse=False)

    # avoid creating pt_chunk to avoid recursion problems
    def inuse(self, p):
        "extract p's inuse bit"
        nextchunk_addr = p.address + (p.size & ~self.SIZE_BITS)
        inferior = hgdb.get_inferior()
        mem = inferior.read_memory(nextchunk_addr + self.SIZE_SZ, self.SIZE_SZ)
        if self.SIZE_SZ == 4:
            nextchunk_size = struct.unpack_from("<I", mem, 0x0)[0]
        elif self.SIZE_SZ == 8:
            nextchunk_size = struct.unpack_from("<Q", mem, 0x0)[0]
        return nextchunk_size & self.PREV_INUSE
        #return (pt_chunk(self, p.address + \
        #        (p.size & ~self.SIZE_BITS), inuse=False).size & self.PREV_INUSE)

    def set_inuse(self, p):
        "set chunk as being inuse without otherwise disturbing"
        chunk = pt_chunk(self, (p.address + (p.size & ~self.SIZE_BITS)), inuse=False)
        chunk.size |= self.PREV_INUSE
        chunk.write()

    def clear_inuse(self, p):
        "clear chunk as being inuse without otherwise disturbing"
        chunk = pt_chunk(self, (p.address + (p.size & ~self.SIZE_BITS)), inuse=False)
        chunk.size &= ~self.PREV_INUSE
        chunk.write()

    def inuse_bit_at_offset(self, p, s):
        "check inuse bits in known places"
        return (pt_chunk(self, (p.address + s), inuse=False).size & self.PREV_INUSE)

    def set_inuse_bit_at_offset(self, p, s):
        "set inuse bits in known places"
        chunk = pt_chunk(self, (p.address + s), inuse=False)
        chunk.size |= self.PREV_INUSE
        chunk.write()

    def clear_inuse_bit_at_offset(self, p, s):
        "clear inuse bits in known places"
        chunk = pt_chunk(self, (p.address + s), inuse=False)
        chunk.size &= ~self.PREV_INUSE
        chunk.write()

    def bin_at(self, m, i):
        "addressing -- note that bin_at(0) does not exist"
        if self.SIZE_SZ == 4:
            offsetof_fd = 0x8
            cast_type = 'unsigned int'
        elif self.SIZE_SZ == 8:
            offsetof_fd = 0x10
            cast_type = 'unsigned long'

        return int(gdb.parse_and_eval("&((struct malloc_state *) 0x%x).bins[%d]" % \
                (m.address, int((i -1) * 2))).cast(gdb.lookup_type(cast_type)) \
                - offsetof_fd)

    def next_bin(self, b):
        return (b + 1)

    def first(self, b):
        return b.fd

    def last(self, b):
        return b.bk

    def in_smallbin_range(self, sz):
        "check if size is in smallbin range"
        return (sz < self.MIN_LARGE_SIZE)

    def smallbin_index(self, sz):
        "return the smallbin index"

        if self.SMALLBIN_WIDTH == 16:
            return (sz >> 4)
        else:
            return (sz >> 3)

    def largebin_index_32(self, sz):
        "return the 32bit largebin index"

        if (sz >> 6) <= 38:
            return (56 + (sz >> 6))
        elif (sz >> 9) <= 20:
            return (91 + (sz >> 9))
        elif (sz >> 12) <= 10:
            return (110 + (sz >> 12))
        elif (sz >> 15) <= 4:
            return (119 + (sz >> 15))
        elif (sz >> 18) <= 2:
            return (124 + (sz >> 18))
        else:
            return 126

    def largebin_index_64(self, sz):
        "return the 64bit largebin index"

        if (sz >> 6) <= 48:
            return (48 + (sz >> 6))
        elif (sz >> 9) <= 20:
            return (91 + (sz >> 9))
        elif (sz >> 12) <= 10:
            return (110 + (sz >> 12))
        elif (sz >> 15) <= 4:
            return (119 + (sz >> 15))
        elif (sz >> 18) <= 2:
            return (124 + (sz >> 18))
        else:
            return 126

    def largebin_index(self, sz):
        "return the largebin index"

        if self.SIZE_SZ == 8:
            return self.largebin_index_64(sz)
        else:
            return self.largebin_index_32(sz)

    def bin_index(self, sz):
        "return the bin index"

        if self.in_smallbin_range(sz):
            return self.smallbin_index(sz)
        else:
            return self.largebin_index(sz)

    def fastbin(self, ar_ptr, idx):
        return ar_ptr.fastbinsY[idx]

    def fastbin_index(self, sz):
        "offset 2 to use otherwise unindexable first 2 bins"
        if self.SIZE_SZ == 8:
            return ((sz >> 4) - 2)
        else:
            return ((sz >> 3) - 2)


    def have_fastchunks(self, M):
        return ((M.flags & self.FASTCHUNKS_BIT) == 0)

    def clear_fastchunks(self, M, inferior=None):
        if inferior == None:
            inferior = hgdb.get_inferior()

        M.flags |= self.FASTCHUNKS_BIT
        inferior.write_memory(M.address, struct.pack("<I", M.flags))

    def set_fastchunks(self, M, inferior=None):
        if inferior == None:
            inferior = hgdb.get_inferior()

        M.flags &= ~self.FASTCHUNKS_BIT
        inferior.write_memory(M.address, struct.pack("<I", M.flags))


    def contiguous(self, M):
        return ((M.flags & self.NONCONTIGUOUS_BIT) == 0)

    def noncontiguous(self, M):
        return ((M.flags & self.NONCONTIGUOUS_BIT) != 0)

    def set_noncontiguous(self, M, inferior=None):
        if inferior == None:
            inferior = hgdb.get_inferior()

        M.flags |= self.NONCONTIGUOUS_BIT
        inferior.write_memory(M.address, struct.pack("<I", M.flags))

    def set_contiguous(self, M, inferior=None):
        if inferior == None:
            inferior = hgdb.get_inferior()

        M.flags &= ~self.NONCONTIGUOUS_BIT
        inferior.write_memory(M.address, struct.pack("<I", M.flags))

    def get_max_fast(self):
        return gdb.parse_and_eval("global_max_fast")

    def top(self, ar_ptr):
        return ar_ptr.top

    def heap_for_ptr(self, ptr):
        "find the heap and corresponding arena for a given ptr"
        return (ptr & ~(self.HEAP_MAX_SIZE-1))

    def print_hexdump(self, p, maxlen=0, off=0):
        data = self.ptr_from_ptmalloc_chunk(p) + off
        size = self.chunksize(p) - p.hdr_size - off
        if size <= 0:
            print("[!] Chunk corrupt? Bad size")
            return
        if maxlen != 0:
            if size > maxlen:
                size = maxlen
        print("0x%x bytes of chunk data:" % size)
        if self.SIZE_SZ == 4:
            cmd = "x/%dwx 0x%x\n" % (size/4, data)
        elif self.SIZE_SZ == 8:
            cmd = "x/%dwx 0x%x\n" % (size/4, data)
            #cmd = "x/%dgx 0x%x\n" % (size/8, data)
            #cmd = "dps 0x%x %d\n" % (data, size/8)
        gdb.execute(cmd, True)
        return

    def chunk_info(self, p):
        info = []
        info.append("0x%lx " % p.address)
        if p.fastchunk_freed == True:
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
                cbinfo["inuse"] = p.inuse
                cbinfo["no_print"] = True
                cbinfo["chunk_info"] = True
                cbinfo["size_sz"] = self.SIZE_SZ

                extra = self.ptchunk_callback(cbinfo)
                if extra:
                    info.append(" " + extra)

        info.append("\b")
        return ''.join(info)

    def search_chunk(self, p, search_for):
        "searches a chunk. includes the chunk header in the search"
        try:
            out_str = gdb.execute('find /1w 0x%x, 0x%x, %s' % \
                (p.address, p.address + p.size, search_for), \
                to_string = True)
        except Exception:
            #print(sys.exc_info()[0])
            self.logmsg("failed to execute 'find'")
            return False

        str_results = out_str.split('\n')

        for str_result in str_results:
            if str_result.startswith('0x'):
                return True

        return False

    def search_chunk(self, p, search_for, depth=0):
        "searches a chunk. includes the chunk header in the search"

        if depth == 0 or depth > self.chunksize(p):
            depth = self.chunksize(p)

        try:
            out_str = gdb.execute('find /1w 0x%x, 0x%x, %s' % \
                (p.address, p.address + depth, search_for), \
                to_string = True)
        except Exception:
            #print(sys.exc_info()[0])
            #print("[libptmalloc] failed to execute 'find'")
            return False

        str_results = out_str.split('\n')

        for str_result in str_results:
            if str_result.startswith('0x'):
                return True

        return False


    def search_heap(self, ar_ptr, search_for, min_size, max_size):
        """walk chunks searching for specified value starting from the
        malloc_state address"""
        results = []

        # XXX - Use global constants for 0x440 and 0x868
        if self.SIZE_SZ == 4:
            p = pt_chunk(self, ar_ptr+0x440+0x0) # need to fix
            print("Not supported yet, need to fix offset")
            return
        elif self.SIZE_SZ == 8:
            # empiric offset: chunks start after the ptmalloc_state + offset
            p = pt_chunk(self, ar_ptr+0x868+0x28)
        heap_size = pt_heap_info(self, self.heap_for_ptr(ar_ptr)).size

        while True:
            if self.chunksize(p) == 0x0:
                self.logmsg("sz=0x0 detected at 0x%x, assuming end of heap" 
                        % p.address)
                break
            if p.address - ar_ptr > heap_size:
                self.logmsg("offset > heap_size detected at 0x%x, assuming end of heap" % p.address)
                break
            if max_size == 0 or self.chunksize(p) <= max_size:
                if self.chunksize(p) >= min_size:
#            print(self.chunk_info(p)) # debug
                    if self.search_chunk(p, search_for):
                        results.append(p.address)
            p = pt_chunk(self, addr=(p.address + self.chunksize(p)))
        return results

    def print_fastbins(self, inferior, fb_base, fb_num):
        "walk and print the fast bins"

        print_title("Fastbins")

        pad_width = 32

        for fb in range(0, self.NFASTBINS):
            if fb_num != None:
                fb = fb_num

            offset = fb_base + fb*self.SIZE_SZ
            try:
                mem = inferior.read_memory(offset, self.SIZE_SZ)
                if self.SIZE_SZ == 4:
                    fd = struct.unpack("<I", mem)[0]
                elif self.SIZE_SZ == 8:
                    fd = struct.unpack("<Q", mem)[0]
            except RuntimeError:
                print_error("Invalid fastbin addr {0:#x}".format(offset))
                return

            print("")
            print_header("[ fb {} ] ".format(fb))
            print("{:#x}{:>{width}}".format(int(offset), "-> ", width=5), end="")
            print_value("[ {:#x} ] ".format(int(fd)))

            if fd != 0: #fastbin is not empty
                fb_size = ((self.MIN_CHUNK_SIZE) +(self.MALLOC_ALIGNMENT)*fb)
                print("({})".format(int(fb_size)))

                chunk = pt_chunk(self, fd, inuse=False)
                while chunk.fd != 0:
                    if chunk.fd is None:
                        # could not read memory section
                        break

                    print_value("{:>{width}}{:#x}{}".format("[ ", int(chunk.fd), " ] ", width=pad_width))
                    print("({})".format(int(fb_size)), end="")

                    chunk = pt_chunk(self, chunk.fd, inuse=False)

            if fb_num != None: #only print one fastbin
                return

    def print_smallbins(self, inferior, sb_base, sb_num):
        "walk and print the small bins"

        print_title("Smallbins")

        pad_width = 33

        for sb in range(2, self.NBINS+2, 2):
            if sb_num != None and sb_num!=0:
                sb = sb_num*2

            offset = sb_base + (sb-2)*self.SIZE_SZ
            try:
                mem = inferior.read_memory(offset, 2*self.SIZE_SZ)
                if self.SIZE_SZ == 4:
                    fd,bk = struct.unpack("<II", mem)
                elif self.SIZE_SZ == 8:
                    fd,bk = struct.unpack("<QQ", mem)
            except RuntimeError:
                print_error("Invalid smallbin addr {0:#x}".format(offset))
                return

            print("")
            print_header("[ sb {:02} ] ".format(int(sb/2)))
            print("{:#x}{:>{width}}".format(int(offset), "-> ", width=5), end="")
            print_value("[ {:#x} | {:#x} ] ".format(int(fd), int(bk)))

            while (1):
                if fd == (offset-2*self.SIZE_SZ):
                    break

                chunk = pt_chunk(self, fd, inuse=False)
                print("")
                print_value("{:>{width}}{:#x} | {:#x} ] ".format("[ ", int(chunk.fd), int(chunk.bk), width=pad_width))
                print("({})".format(int(self.chunksize(chunk))), end="")
                fd = chunk.fd

            if sb_num != None: #only print one smallbin
                return

    def print_bins(self, inferior, fb_base, sb_base):
        "walk and print the nonempty free bins, modified from jp"

        print_title("Heap Dump")

        for fb in range(0,self.NFASTBINS):
            print_once = True
            p = pt_chunk(self, fb_base-(2*self.SIZE_SZ)+fb*self.SIZE_SZ, inuse=False)

            while (p.fd != 0):
                if p.fd is None:
                    break

                if print_once:
                    print_once = False
                    print_header("fast bin {} @ {:#x}".format(fb, int(p.fd)))
                print("\n\tfree chunk @ ", end="")
                print_value("{:#x} ".format(int(p.fd)))
                print("- size ", end="")
                p = pt_chunk(self, p.fd, inuse=False)
                print_value("{:#x} ".format(int(self.chunksize(p))))

        for i in range(1, self.NBINS):
            print_once = True
            b = sb_base + i*2*self.SIZE_SZ - 4*self.SIZE_SZ
            p = pt_chunk(self, self.first(pt_chunk(self, b, inuse=False)), inuse=False)

            while p.address != int(b):
                print("")
                if print_once:
                    print_once = False
                    if i==1:
                        try:
                            print_header("unsorted bin @ ")
                            print_value("{:#x}".format(int(\
                                    b.cast(gdb.lookup_type("unsigned long")) + 2*self.SIZE_SZ)))
                        except Exception:
                            print_header("unsorted bin @ ")
                            print_value("{:#x}".format(int(b + 2*self.SIZE_SZ)))
                    else:
                        try:
                            print_header("small bin {} @ ".format(i))
                            print_value("{:#x}".format(int(b.cast(gdb.lookup_type("unsigned long")) + 2*self.SIZE_SZ)))
                        except Exception:
                            print_header("small bin {} @ ".format(i))
                            print_value("{:#x}".format(int(b + 2*self.SIZE_SZ)))

                print("\n\tfree chunk @ ",end="")
                print_value("{:#x} ".format(int(p.address)))
                print("- size ",end="")
                print_value("{:#x}".format(int(self.chunksize(p))))
                p = pt_chunk(self, self.first(p), inuse=False)

    def print_flat_listing(self, ar_ptr, sbrk_base):
        "print a flat listing of an arena, modified from jp and arena.c"

        print_title("Heap Dump")
        print_header("\n{:>14}{:>17}{:>15}\n".format("ADDR", "SIZE", "STATUS"))
        print("sbrk_base ", end="")
        print("{:#x}".format(int(sbrk_base)))

        p = pt_chunk(self, sbrk_base, inuse=True)

        while(1):
            print("chunk     {:#x}{:>11}{:<8x}{:>3}".format(int(p.address),"0x",int(self.chunksize(p)),""),end="")

            if p.address == self.top(ar_ptr):
                print("(top)")
                break
            elif p.size == (0|self.PREV_INUSE):
                print("(fence)")
                break

            if self.inuse(p):
                print("(inuse)")
            else:
                p = pt_chunk(self, p.address, inuse=False)
                print("(F) FD ", end="")
                print_value("{:#x} ".format(int(p.fd)))
                print("BK ", end="")
                print_value("{:#x} ".format(int(p.bk)))

                if ((p.fd == ar_ptr.last_remainder) \
                and (p.bk == ar_ptr.last_remainder) \
                and (ar_ptr.last_remainder != 0)):
                    print("(LR)")
                elif ((p.fd == p.bk) & ~self.inuse(p)):
                    print("(LC)")
                else:
                    print("")

            p = pt_chunk(self, self.next_chunk(p), inuse=True)

        print("sbrk_end  ", end="")
        print("{:#x}".format(int(sbrk_base + ar_ptr.max_system_mem)), end="")

    def print_compact_listing(self, ar_ptr, sbrk_base):
        "print a compact layout of the heap, modified from jp"

        print_title("Heap Dump")
        p = pt_chunk(self, sbrk_base, inuse=True)

        while(1):
            if p.address == self.top(ar_ptr):
                sys.stdout.write("|T|\n")
                break

            if self.inuse(p):
                sys.stdout.write("|A|")
            else:
                p = pt_chunk(self, p.address, inuse=False)

                if ((p.fd == ar_ptr.last_remainder) \
                and (p.bk == ar_ptr.last_remainder) \
                and (ar_ptr.last_remainder != 0)):
                    sys.stdout.write("|L|")
                else:
                    sys.stdout.write("|%d|" % self.bin_index(p.size))

            p = pt_chunk(self, self.next_chunk(p), inuse=True)

################################################################################
# STRUCTURES
################################################################################

# similar to *_structure in other files
class pt_structure(object):

    def __init__(self, pt, inferior=None):
        self.pt = pt
        self.is_x86 = self.pt.SIZE_SZ == 4
        self.initOK = True
        self.address = None

        if inferior == None:
            self.inferior = hgdb.get_inferior()
            if self.inferior == -1:
                self.pt.logmsg("Error obtaining gdb inferior")
                self.initOK = False
                return
        else:
            self.inferior = inferior

    def _get_cpu_register(self, reg):
        """
        Get the value holded by a CPU register
        """

        expr = ''
        if reg[0] == '$':
            expr = reg
        else:
            expr = '$' + reg

        try:
            val = self._normalize_long(long(gdb.parse_and_eval(expr)))
        except Exception:
            print("Have you run the process? Can't retrieve registers")
            return None
        return val

    def _normalize_long(self, l):
        return (0xffffffff if self.is_x86 else 0xffffffffffffffff) & l

    def _is_register(self, s):
        """
        bin_size Is it a valid register ?
        """
        x86_reg = ['eax', 'ebx', 'ecx', 'edx', 'esi',
                   'edi', 'esp', 'ebp', 'eip']
        x64_reg = ['rax', 'rbx', 'rcx', 'rdx', 'rsi',
                   'rdi', 'rsp', 'rbp', 'rip'] \
                   + ['r%d' % i for i in range(8, 16)]

        if s[0] == '$':
            s = s[1:]

        if s in (x86_reg if self.is_x86 else x64_reg):
            return True
        return False

    def _parse_base_offset(self, r):
        base = r
        offset = 0
        if "+" in r:
            # we assume it is a register or address + a hex value
            tmp = r.split("+")
            base = tmp[0]
            offset = int(tmp[1], 16)
        if "-" in r:
            # we assume it is a register or address - a hex value
            tmp = r.split("-")
            base = tmp[0]
            offset = int(tmp[1], 16)*-1
        if self._is_register(base):
            base = self._get_cpu_register(base)
            if not base:
                return None
        else:
            try:
                # we assume it's an address
                base = int(base, 16)
            except Exception:
                print('Error: not an address')
                return None
        return base, offset

    def validate_addr(self, addr):
        if addr == None or addr == 0:
            print('[libptmalloc] invalid address')
            self.initOK = False
            self.address = None
            return False
        elif type(addr) == str:
            res = self._parse_base_offset(addr)
            if res == None:
                self.pt.logmsg('First arg MUST be either an address or a register (+ optional offset)"')
                self.initOK = False
                return False
            self.address = res[0] + res[1]
        else:
            self.address = addr
        return True

################################################################################
class pt_chunk(pt_structure):
    "python representation of a struct malloc_chunk"

    def __init__(self, pt, addr=None, mem=None, size=None, inferior=None,
            inuse=None):
        super(pt_chunk, self).__init__(pt, inferior)
        if not self.initOK:
            return

        self.prev_size   = 0
        self.size        = 0
        # free specific
        self.fd          = None
        self.bk          = None
        # large blocks specific + free specific
        self.fd_nextsize = None
        self.bk_nextsize = None

        # actual chunk flags
        self.cinuse_bit  = 0

        # fast chunk do not have their cinuse bit set when they are free
        # instead we keep the info here
        self.fastchunk_freed = False

        # general indicator if we are inuse
        self.inuse       = inuse

        self.data_address = None
        self.hdr_size = 0

        if not self.validate_addr(addr):
            return

        # read the minimum chunk size first to determine the chunk size
        # this also treats the case where chunk is inuse
        if mem == None:
            # a string of raw memory was not provided
            try:
                mem = self.inferior.read_memory(addr, self.pt.INUSE_HDR_SZ)
            except TypeError:
                self.pt.logmsg("Invalid address specified.")
                self.initOK = False
                return
            except RuntimeError:
                self.pt.logmsg("Could not read address {0:#x}".format(addr))
                self.initOK = False
                return
        else:
            # a string of raw memory was provided
            if self.inuse == True:
                if (len(mem)<self.pt.INUSE_HDR_SZ):
                    self.pt.logmsg("Insufficient memory provided for a malloc_chunk.")
                    self.initOK = False
                    return
            else:
                if (len(mem)<self.pt.FREE_HDR_SZ):
                    self.pt.logmsg("Insufficient memory provided for a free chunk.")
                    self.initOK = False
                    return
        if self.pt.SIZE_SZ == 4:
            (self.prev_size,
            self.size) = struct.unpack_from("<II", mem, 0x0)
        elif self.pt.SIZE_SZ == 8:
            (self.prev_size,
            self.size) = struct.unpack_from("<QQ", mem, 0x0)

        if self.size == 0:
            self.pt.logmsg("chunk with zero size detected at 0x%x" % self.address)
            self.initOK = False
            return

        # read next chunk size field to determine if current chunk is inuse
        if size == None:
            nextchunk_addr = self.address + (self.size & ~self.pt.SIZE_BITS)
        else:
            nextchunk_addr = self.address + (size & ~self.pt.SIZE_BITS)
        try:
            mem2 = self.inferior.read_memory(nextchunk_addr + self.pt.SIZE_SZ, 
                    self.pt.SIZE_SZ)
        except gdb.MemoryError:
            self.pt.logmsg("Could not read nextchunk's size. Invalid chunk address?")
            self.initOK = False
            return
        if self.pt.SIZE_SZ == 4:
            nextchunk_size = struct.unpack_from("<I", mem2, 0x0)[0]
        elif self.pt.SIZE_SZ == 8:
            nextchunk_size = struct.unpack_from("<Q", mem2, 0x0)[0]
        self.cinuse_bit = nextchunk_size & self.pt.PREV_INUSE

        # XXX - hax (see TODO in file header). This shouldn't be released in
        # public version
        # Even if it shows allocated, we need to check it is not a fastchunk
        # We do it by looking if the mh_magic is after prev_size/size
        # One option is to walk the associated fastbin entry if it would fit in
        # one, but this is hella slow over serial.
        if self.cinuse_bit:
            mem = self.inferior.read_memory(addr + 2*self.pt.SIZE_SZ, 4)
            next_word = struct.unpack_from("<I", mem, 0x0)[0]
            if next_word != 0xa11c0123:
                self.fastchunk_freed = True

        # safe if chunk is actually inuse
        if inuse == None:
            if self.cinuse_bit and not self.fastchunk_freed:
                self.inuse = True
            else:
                self.inuse = False
        else:
            # Trust the caller is right
            self.inuse = inuse

        # now that we know the size and if it is inuse/freed, we can determine 
        # the chunk type and though the chunk header size
        if self.inuse == True:
            self.hdr_size = self.pt.INUSE_HDR_SZ
        else:
            if size == None:
                if self.fastchunk_freed:
                    self.hdr_size = self.pt.FREE_FASTCHUNK_HDR_SZ
                elif self.pt.in_smallbin_range(self.size):
                    self.hdr_size = self.pt.FREE_HDR_SZ
                else:
                    self.hdr_size = self.pt.FREE_LARGE_HDR_SZ
            else:
                # Trust the caller size
                if self.pt.in_smallbin_range(size):
                    self.hdr_size = self.pt.FREE_HDR_SZ
                else:
                    self.hdr_size = self.pt.FREE_LARGE_HDR_SZ

        # parse additional fields in chunk header depending on type
        # fastbins freed follows
        if self.hdr_size == self.pt.FREE_FASTCHUNK_HDR_SZ:
            if self.address != None:
                # a string of raw memory was not provided
                if self.inferior != None:
                    if self.pt.SIZE_SZ == 4:
                        mem = self.inferior.read_memory(self.address,
                                self.pt.FREE_FASTCHUNK_HDR_SZ)
                    elif self.pt.SIZE_SZ == 8:
                        mem = self.inferior.read_memory(self.address, 
                                self.pt.FREE_FASTCHUNK_HDR_SZ)
            if self.pt.SIZE_SZ == 4:
                self.fd = struct.unpack_from("<I", mem, self.pt.INUSE_HDR_SZ)[0]
            elif self.pt.SIZE_SZ == 8:
                self.fd = struct.unpack_from("<Q", mem, self.pt.INUSE_HDR_SZ)[0]
        # smallbin freed follows
        elif self.hdr_size == self.pt.FREE_HDR_SZ:
            if self.address != None:
                # a string of raw memory was not provided
                if self.inferior != None:
                    if self.pt.SIZE_SZ == 4:
                        mem = self.inferior.read_memory(self.address, 
                                self.pt.FREE_HDR_SZ)
                    elif self.pt.SIZE_SZ == 8:
                        mem = self.inferior.read_memory(self.address, 
                                self.pt.FREE_HDR_SZ)
            if self.pt.SIZE_SZ == 4:
                (self.fd,
                self.bk) = struct.unpack_from("<II", mem, self.pt.INUSE_HDR_SZ)
            elif self.pt.SIZE_SZ == 8:
                (self.fd,
                self.bk) = struct.unpack_from("<QQ", mem, self.pt.INUSE_HDR_SZ)
        # largebin freed freed follows
        elif self.hdr_size == self.pt.FREE_LARGE_HDR_SZ:
            if self.address != None:
                # a string of raw memory was not provided
                if self.inferior != None:
                    if self.pt.SIZE_SZ == 4:
                        mem = self.inferior.read_memory(self.address,
                                self.pt.FREE_LARGE_HDR_SZ)
                    elif self.pt.SIZE_SZ == 8:
                        mem = self.inferior.read_memory(self.address,
                                self.pt.FREE_LARGE_HDR_SZ)
            if self.pt.SIZE_SZ == 4:
                (self.fd,         \
                self.bk,          \
                self.fd_nextsize, \
                self.bk_nextsize) = struct.unpack_from("<IIII", mem,
                    self.pt.INUSE_HDR_SZ)
            elif self.pt.SIZE_SZ == 8:
                (self.fd,         \
                self.bk,          \
                self.fd_nextsize, \
                self.bk_nextsize) = struct.unpack_from("<QQQQ", mem, 
                    self.pt.INUSE_HDR_SZ)

        # keep track where the data follows
        if self.address != None:
            self.data_address = self.address + self.hdr_size

    def __str__(self):
        if self.prev_size == 0 and self.size == 0:
            return ""
        # XXX - since they all share the same prev_size/size and 2 chunk types
        # also share the fd/bk, we could refactor code here?
        elif self.hdr_size == self.pt.INUSE_HDR_SZ:
            ret = "struct malloc_chunk @ "
            ret += "{:#x} ".format(self.address)
            ret += "{"
            ret += "\n{:11} = ".format("prev_size")
            ret += "{:#x}".format(self.prev_size)
            ret += "\n{:11} = ".format("size")
            ret += "{:#x}".format(self.size & ~self.pt.SIZE_BITS)

            if self.pt.prev_inuse(self) or self.pt.chunk_is_mmapped(self) or \
                    self.pt.chunk_non_main_arena(self):
                ret += " ("
                if self.pt.prev_inuse(self):
                    ret += "PREV_INUSE|"
                if self.pt.chunk_is_mmapped(self):
                    ret += "MMAPPED|"
                if self.pt.chunk_non_main_arena(self):
                    ret += "NON_MAIN_ARENA|"
                ret += "\b)"
            return ret
        elif self.hdr_size == self.pt.FREE_FASTCHUNK_HDR_SZ:
            ret = "struct malloc_chunk @ "
            ret += "{:#x} ".format(self.address)
            ret += "{"
            ret += "\n{:11} = ".format("prev_size")
            ret += "{:#x}".format(self.prev_size)
            ret += "\n{:11} = ".format("size")
            ret += "{:#x}".format(self.size & ~self.pt.SIZE_BITS)
            flag_str = ''
            if self.pt.prev_inuse(self):
                flag_str += "PREV_INUSE|"
            if self.pt.chunk_is_mmapped(self):
                flag_str += "MMAPPED|"
            if self.pt.chunk_non_main_arena(self):
                flag_str += "NON_MAIN_ARENA|"
            if len(flag_str) != 0:
                ret += " ("
                ret += flag_str
                ret += "\b)"
            ret += "\n{:11} = ".format("fd")
            ret += "{:#x}".format(self.fd)
            return ret
        elif self.hdr_size == self.pt.FREE_HDR_SZ:
            ret = "struct malloc_chunk @ "
            ret += "{:#x} ".format(self.address)
            ret += "{"
            ret += "\n{:11} = ".format("prev_size")
            ret += "{:#x}".format(self.prev_size)
            ret += "\n{:11} = ".format("size")
            ret += "{:#x}".format(self.size & ~self.pt.SIZE_BITS)
            ret += " ("
            if self.pt.prev_inuse(self):
                ret += "PREV_INUSE|"
            if self.pt.chunk_is_mmapped(self):
                ret += "MMAPPED|"
            if self.pt.chunk_non_main_arena(self):
                ret += "NON_MAIN_ARENA|"
            ret += "\b)"
            ret += "\n{:11} = ".format("fd")
            ret += "{:#x}".format(self.fd)
            ret += "\n{:11} = ".format("bk")
            ret += "{:#x}".format(self.bk)
            return ret
        elif self.hdr_size == self.pt.FREE_LARGE_HDR_SZ:
            ret = color_title("struct malloc_chunk @ ")
            ret += "{:#x} ".format(self.address)
            ret += "{"
            ret += "\n{:11} = ".format("prev_size")
            ret += "{:#x}".format(self.prev_size)
            ret += "\n{:11} = ".format("size")
            ret += "{:#x}".format(self.size & ~self.pt.SIZE_BITS)
            ret += " ("
            if self.pt.prev_inuse(self):
                ret += "PREV_INUSE|"
            if self.pt.chunk_is_mmapped(self):
                ret += "MMAPPED|"
            if self.pt.chunk_non_main_arena(self):
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
            self.pt.logmsg("Error: unknown hdr_size. Should not happen")
            return ""

###############################################################################
class pt_heap_info(pt_structure):
    "python representation of a struct heap_info"

    def __init__(self, pt, addr=None, mem=None, inferior=None):
        super(pt_heap_info, self).__init__(pt)
        self.ar_ptr             = 0
        self.prev               = 0
        self.size               = 0
        self.mprotect_size      = 0
        self.pad                = 0

        if addr == None:
            if mem == None:
                print_error("Please specify a struct pt_heap_info address.")
                return None

            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = hgdb.get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if self.pt.SIZE_SZ == 4:
                    print("pt_heap_info not supported yet")
                    return
                    #mem = inferior.read_memory(addr, 0x0)
                elif self.pt.SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x20)
            except TypeError:
                print_error("Invalid address specified.")
                return None
            except RuntimeError:
                print_error("Could not read address {0:#x}".format(addr))
                return None

        if self.pt.SIZE_SZ == 4:
            pass # XXX
        elif self.pt.SIZE_SZ == 8:
            (self.ar_ptr,       \
            self.prev,          \
            self.size,          \
            self.mprotect_size) = struct.unpack_from("<QQQQ", mem, 0x0)

    def __str__(self):
        hi = color_title("struct heap_info {")
        hi += "\n{:14} = ".format("ar_ptr")
        hi += color_value("{:#x}".format(self.ar_ptr))
        hi += "\n{:14} = ".format("prev")
        hi += color_value("{:#x}".format(self.prev))
        hi += "\n{:14} = ".format("size")
        hi += color_value("{:#x}".format(self.size))
        hi += "\n{:14} = ".format("mprotect_size")
        hi += color_value("{:#x}".format(self.mprotect_size))
        return hi

# unfinished - not working yet
class pt_save_state(pt_structure):
    "python representation of a struct malloc_save_state"

    def __init__(self, pt, addr=None, mem=None, inferior=None):
        super(pt_save_state, self).__init__(pt)
        self.magic = 0
        self.version = 0
        self.av = []
        self.sbrk_base = 0
        self.sbrked_mem_bytes = 0
        self.trim_threshold = 0
        self.top_pad = 0
        self.n_mmaps_max = 0
        self.mmap_threshold = 0
        self.check_action = 0
        self.max_sbrked_mem = 0
        self.max_total_mem = 0
        self.n_mmaps = 0
        self.max_n_mmaps = 0
        self.mmapped_mem = 0
        self.max_mmapped_mem = 0
        self.using_malloc_checking = 0
        self.max_fast = 0
        self.arena_test = 0
        self.arena_max = 0
        self.narenas = 0
        self.str_name = "malloc_save_state"

        if addr == None:
            if mem == None:
                print_error("Please specify a struct malloc_save_state address.")
                return None

            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = hgdb.get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if self.pt.SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x700) # XXX - FIX SIZE
                elif self.pt.SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x8a8) # XXX - FIX SIZE
            except TypeError:
                print_error("Invalid address specified.")
                return None
            except RuntimeError:
                print_error("Could not read address {0:#x}".format(addr))
                return None


        if self.pt.SIZE_SZ == 4:
            pass # XXX
        elif self.pt.SIZE_SZ == 8:
            av_off = 0x8
            sbrk_base_off = av_off + self.pt.NBINS*2 + 2
            (self.magic,
            self.version) = struct.unpack_from("<QQ", mem, 0x0)
            self.av = self.av # XXX unpack
            (self.sbrk_base,
            self.sbrked_mem_bytes,
            self.trim_threshold,
            self.top_pad,
            self.n_mmaps_max,
            self.mmap_threshold ,
            self.check_action,
            self.max_sbrked_mem,
            self.max_total_mem,
            self.n_mmaps,
            self.max_n_mmaps,
            self.mmapped_mem,
            self.max_mmapped_mem,
            self.using_malloc_checking,
            self.max_fast,
            self.arena_test,
            self.arena_max,
            self.narenas) = struct.unpack_from("<QQQQQQQQQIIQQQQQQQ", mem, 
                sbrk_base_off)

    def __str__(self):
        string = []
        string.append("%s%lx%s%s%lx%s%lx%s%lx%s%lx" %
                ("struct " + self.str_name + " @ 0x",
                self.address,
                " {",
                "\nmagic      = 0x",
                self.magic,
                "\nmversion        = 0x",
                self.version,
                "\n...",
                0,
                "\nmmapped_mem  = 0x",
                self.mmapped_mem))
        return ''.join(string)

################################################################################
# XXX - fix all pointers to be 64bit when displaying them
# XXX - support a verbose to display/hide bins[], fastbinsY[]
class pt_arena(pt_structure):
    "python representation of a struct malloc_state which represents an arena"

    def __init__(self, pt, addr=None, mem=None, inferior=None):
        super(pt_arena, self).__init__(pt)
        self.mutex          = 0
        self.flags          = 0
        self.fastbinsY      = 0
        self.top            = 0
        self.last_remainder = 0
        self.bins           = 0
        self.binmap         = 0
        self.next           = 0
        self.next_free      = 0
        self.system_mem     = 0
        self.max_system_mem = 0

        if addr == None:
            if mem == None:
                print_error("Please specify a struct malloc_mstate address.")
                return None

            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = hgdb.get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if self.pt.SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x450)
                elif self.pt.SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x888)
            except TypeError:
                print_error("Invalid address specified.")
                return None
            except RuntimeError:
                print_error("Could not read address {0:#x}".format(addr))
                return None

        if self.pt.SIZE_SZ == 4:
            (self.mutex,         \
            self.flags)          = struct.unpack_from("<II", mem, 0x0)
            self.fastbinsY       = struct.unpack_from("<10I", mem, 0x8)
            (self.top,           \
            self.last_remainder) = struct.unpack_from("<II", mem, 0x30)

            self.bins            = struct.unpack_from("<254I", mem, 0x38)
            self.binmap          = struct.unpack_from("<IIII", mem, 0x430)
            (self.next,          \
            self.next_free,          \
            self.system_mem,     \
            self.max_system_mem) = struct.unpack_from("<IIII", mem, 0x440)
        elif self.pt.SIZE_SZ == 8:
            (self.mutex,         \
            self.flags)          = struct.unpack_from("<II", mem, 0x0)
            self.fastbinsY       = struct.unpack_from("<10Q", mem, 0x8)
            (self.top,           \
            self.last_remainder) = struct.unpack_from("<QQ", mem, 0x58)
            self.bins            = struct.unpack_from("<254Q", mem, 0x68)
            self.binmap          = struct.unpack_from("<IIII", mem, 0x858)
            (self.next,          \
            self.next_free,          \
            self.system_mem,     \
            self.max_system_mem) = struct.unpack_from("<QQQQ", mem, 0x868)

        self.pt.pt_cached_mstate = self

    def __str__(self):
        ms = color_title("struct malloc_mstate {")
        ms += "\n{:14} = ".format("mutex")
        ms += color_value("{:#x}".format(self.mutex))
        ms += "\n{:14} = ".format("flags")
        ms += color_value("{:#x}".format(self.flags))
        # XXX - make this look nicer in output
        #ms += "\n{:14} = ".format("fastbinsY")
        #ms += color_value("{}".format("{...}"))
        i = 0
        while i < len(self.fastbinsY):
            ms += "\n{:11} = ".format("fastbinY[%d]" % i)
            ms += color_value("{:#x}".format(self.fastbinsY[i]))
            i += 1
        ms += "\n{:14} = ".format("top")
        ms += color_value("{:#x}".format(self.top))
        ms += "\n{:14} = ".format("last_remainder")
        ms += color_value("{:#x}".format(self.last_remainder))
        # Add a check to see if we point to ourself, meaning we are empty
        # XXX - make this look nicer in output
        #ms += "\n{:14} = ".format("bins")
        #ms += color_value("{}".format("{...}"))
        i = 0
        while i < len(self.bins):
            ms += "\n{:11} = ".format("bin[%d]: " % int(i / 2))
            ms += color_value("{:#x}, ".format(self.bins[i]))
            ms += color_value("{:#x}".format(self.bins[i+1]))
            i += 2
        # XXX - make this look nicer in output
        #ms += "\n{:14} = ".format("binmap")
        #ms += color_value("{}".format("{...}"))
        i = 0
        while i < len(self.binmap):
            ms += "\n{:11} = ".format("binmap[%d]" % i)
            ms += color_value("{:#x}".format(self.binmap[i]))
            i += 1
        ms += "\n{:14} = ".format("next")
        ms += color_value("{:#x}".format(self.next))
        ms += "\n{:14} = ".format("next_free")
        ms += color_value("{:#x}".format(self.next_free))
        ms += "\n{:14} = ".format("system_mem")
        ms += color_value("{:#x}".format(self.system_mem))
        ms += "\n{:14} = ".format("max_system_mem")
        ms += color_value("{:#x}".format(self.max_system_mem))
        return ms

################################################################################
class pt_malloc_par(pt_structure):
    "python representation of a struct malloc_par"

    def __init__(self, pt, addr=None, mem=None, inferior=None):
        super(pt_malloc_par, self).__init__(pt)
        self.trim_threshold   = 0
        self.top_pad          = 0
        self.mmap_threshold   = 0
        self.arena_test       = 0
        self.arena_max        = 0
        self.n_mmaps          = 0
        self.n_mmaps_max      = 0
        self.max_n_mmaps      = 0
        self.no_dyn_threshold = 0
        self.mmapped_mem      = 0
        self.max_mmapped_mem  = 0
        self.max_total_mem    = 0
        self.sbrk_base        = 0

        if addr == None:
            if mem == None:
                print_error("Please specify a struct malloc_par address.")
                return None

            self.address = None
        else:
            self.address = addr

        if inferior == None and mem == None:
            inferior = hgdb.get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if self.pt.SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x34)
                elif self.pt.SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x58)
            except TypeError:
                print_error("Invalid address specified.")
                return None
            except RuntimeError:
                print_error("Could not read address {0:#x}".format(addr))
                return None

        if self.pt.SIZE_SZ == 4:
            (self.trim_threshold, \
            self.top_pad,         \
            self.mmap_threshold,  \
            self.arena_text,      \
            self.arena_max,       \
            self.n_mmaps,         \
            self.n_mmaps_max,     \
            self.max_n_mmaps,     \
            self.no_dyn_threshold,\
            self.mmapped_mem,     \
            self.max_mmapped_mem, \
            self.max_total_mem,   \
            self.sbrk_base)       = struct.unpack("<13I", mem)
        elif self.pt.SIZE_SZ == 8:
            (self.trim_threshold, \
            self.top_pad,         \
            self.mmap_threshold,  \
            self.arena_test,      \
            self.arena_max,       \
            self.n_mmaps,         \
            self.n_mmaps_max,     \
            self.max_n_mmaps,     \
            self.no_dyn_threshold,\
            self.mmapped_mem,     \
            self.max_mmapped_mem, \
            self.max_total_mem,   \
            self.sbrk_base)       = struct.unpack("<5Q4I4Q", mem)

        # work around for sbrk_base
        # if we cat get sbrk_base from mp_, we read the heap base from vmmap.
        if self.sbrk_base == 0:
            pid, task_id, thread_id = gdb.selected_thread().ptid
            maps_data = open("/proc/%d/task/%d/maps" %
                    (pid, task_id)).readlines()
            for line in maps_data:
                if any(x.strip() == '[heap]' for x in line.split(' ')):
                    self.sbrk_base = int(line.split(' ')[0].split('-')[0], 16)
                    break

    def __str__(self):
        mp = color_title("struct malloc_par {")
        mp += "\n{:16} = ".format("trim_threshold")
        mp += color_value("{:#x}".format(self.trim_threshold))
        mp += "\n{:16} = ".format("top_pad")
        mp += color_value("{:#x}".format(self.top_pad))
        mp += "\n{:16} = ".format("mmap_threshold")
        mp += color_value("{:#x}".format(self.mmap_threshold))
        mp += "\n{:16} = ".format("arena_test")
        mp += color_value("{:#x}".format(self.arena_test))
        mp += "\n{:16} = ".format("arena_max")
        mp += color_value("{:#x}".format(self.arena_max))
        mp += "\n{:16} = ".format("n_mmaps")
        mp += color_value("{:#x}".format(self.n_mmaps))
        mp += "\n{:16} = ".format("n_mmaps_max")
        mp += color_value("{:#x}".format(self.n_mmaps_max))
        mp += "\n{:16} = ".format("max_n_mmaps")
        mp += color_value("{:#x}".format(self.max_n_mmaps))
        mp += "\n{:16} = ".format("no_dyn_threshold")
        mp += color_value("{:#x}".format(self.no_dyn_threshold))
        mp += "\n{:16} = ".format("mmapped_mem")
        mp += color_value("{:#x}".format(self.mmapped_mem))
        mp += "\n{:16} = ".format("max_mmapped_mem")
        mp += color_value("{:#x}".format(self.max_mmapped_mem))
        mp += "\n{:16} = ".format("max_total_mem")
        mp += color_value("{:#x}".format(self.max_total_mem))
        mp += "\n{:16} = ".format("sbrk_base")
        mp += color_value("{:#x}".format(self.sbrk_base))
        return mp

################################################################################
# GDB COMMANDS
################################################################################

# This is a super class with few convenience methods to let all the cmds parse
# gdb variables easily
class ptcmd(gdb.Command):

    def __init__(self, pt, name):
        self.pt = pt
        super(ptcmd, self).__init__(name, gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def logmsg(self, s, end=None):
        if type(s) == str:
            if end != None:
                print("[libptmalloc] " + s, end=end)
            else:
                print("[libptmalloc] " + s)
        else:
            print(s)

    def parse_var(self, var):
        if self.pt.SIZE_SZ == 4:
            p = self.tohex(int(gdb.parse_and_eval(var)), 32)
        elif self.pt.SIZE_SZ == 8:
            p = self.tohex(int(gdb.parse_and_eval(var)), 64)
        return int(p, 16)

    def tohex(self, val, nbits):
        result = hex((val + (1 << nbits)) % (1 << nbits))
        # -1 because hex() only sometimes tacks on a L to hex values...
        if result[-1] == 'L':
            return result[:-1]
        else:
            return result

###############################################################################
# XXX - fix if needed
class ptstats(ptcmd):
    "print general malloc stats, adapted from malloc.c mSTATs()"

    def __init__(self, pt):
        super(ptstats, self).__init__(pt, "print_mstats")

    def invoke(self, arg, from_tty):
        "Specify an optional arena addr: print_mstats main_arena=0x12345"

        try:
            mp = gdb.selected_frame().read_var('mp_')

            if arg.find("main_arena") == -1:
                main_arena = gdb.selected_frame().read_var('main_arena')
                main_arena_address = main_arena.address
            else:
                arg = arg.split()
                for item in arg:
                    if item.find("main_arena") != -1:
                        if len(item) < 12:
                            print_error("Malformed main_arena parameter")
                            return
                        else:
                            main_arena_address = int(item[11:],16)
        except RuntimeError:
            print_error("No frame is currently selected.")
            return
        except ValueError:
            print_error("Debug glibc was not found.")
            return

        if main_arena_address == 0:
            print_error("Invalid main_arena address (0)")
            return

        mp = pt_save_state(self.pt, mp_address)
        in_use_b = mp.mmapped_mem
        system_b = in_use_b

        print_title("Malloc Stats")

        arena = 0
        ar_ptr = pt_arena(self.pt, main_arena_address)
        while(1):
            hgdb.mutex_lock(ar_ptr)

            # account for top
            avail = self.pt.chunksize(pt_chunk(self.pt, self.pt.top(ar_ptr), inuse=True))
            nblocks = 1

            nfastblocks = 0
            fastavail = 0

            # traverse fastbins
            for i in range(self.pt.NFASTBINS):
                p = self.pt.fastbin(ar_ptr, i)
                while p!=0:
                    p = pt_chunk(self.pt, p, inuse=False)
                    nfastblocks += 1
                    fastavail += self.pt.chunksize(p)
                    p = p.fd

            avail += fastavail

            # traverse regular bins
            for i in range(1, self.pt.NBINS):
                b = self.pt.bin_at(ar_ptr, i)
                p = pt_chunk(self.pt.first(pt_chunk(self.pt, b,inuse=False)), 
                        inuse=False)

                while p.address != int(b):
                    nblocks += 1
                    avail += self.pt.chunksize(p)
                    p = pt_chunk(self.pt, self.pt.first(p), inuse=False)

            print_header("Arena {}:\n".format(arena))
            print("{:16} = ".format("system bytes"), end='')
            print_value("{}".format(ar_ptr.max_system_mem), end='\n')
            print("{:16} = ".format("in use bytes"), end='')
            print_value("{}".format(ar_ptr.max_system_mem - avail), end='\n')

            system_b += ar_ptr.max_system_mem
            in_use_b += (ar_ptr.max_system_mem - avail)

            hgdb.mutex_unlock(ar_ptr)
            if ar_ptr.next == main_arena_address:
                break
            else:
                ar_ptr = pt_arena(self.pt, ar_ptr.next)
                arena += 1

        print_header("Total (including mmap):\n")
        print("{:16} = ".format("system bytes"), end='')
        print_value("{}".format(system_b), end='\n')
        print("{:16} = ".format("in use bytes"), end='')
        print_value("{}".format(in_use_b), end='\n')
        print("{:16} = ".format("max system bytes"), end='')
        print_value("{}".format(mp['max_total_mem']), end='\n')
        print("{:16} = ".format("max mmap regions"), end='')
        print_value("{}".format(mp['max_n_mmaps']), end='\n')
        print("{:16} = ".format("max mmap bytes"), end='')
        print_value("{}".format(mp['max_mmapped_mem']), end='\n')

################################################################################
class ptcallback(ptcmd):
    "Manage callbacks"

    def __init__(self, pt):
        super(ptcallback, self).__init__(pt, "ptcallback")

    def help(self):
        self.pt.logmsg('usage: ptcallback <options>')
        self.pt.logmsg(' disable         temporarily disable the registered callback')
        self.pt.logmsg(' enable          enable the registered callback')
        self.pt.logmsg(' status          check if a callback is registered')
        self.pt.logmsg(' clear           forget the registered callback')
        self.pt.logmsg(' register <name> use a global function <name> as callback')
        self.pt.logmsg(' register <name> <module> use a global function <name> as callback from <module>')

    def invoke(self, arg, from_tty):
        if arg == '':
            self.help()
            return

        arg = arg.lower()
        if arg.find("enable") != -1:
            self.pt.ptchunk_callback = self.pt.ptchunk_callback_cached
            self.pt.logmsg('callback enabled')
            if self.pt.ptchunk_callback == None:
                self.pt.logmsg('NOTE: callback was enabled, but is unset')
        elif arg.find("disable") != -1:
            self.pt.ptchunk_callback_cached = self.pt.ptchunk_callback
            self.pt.ptchunk_callback = None
            self.pt.logmsg('callback disabled')
        elif arg.find("clear") != -1:
            self.pt.ptchunk_callback = None
            self.pt.ptchunk_callback_cached = None
            self.pt.logmsg('callback cleared')
        elif arg.find("status") != -1:
            if self.pt.ptchunk_callback:
                self.pt.logmsg('a callback is registered and enabled')
            elif self.pt.ptchunk_callback == None and \
                    self.pt.ptchunk_callback_cached:
                self.pt.logmsg('a callback is registered and disabled')
            else:
                self.pt.logmsg('a callback is not registered')
        elif arg.find("register") != -1:
            args = arg.split(' ')
            if len(args) < 2:
                self.pt.logmsg('[!] Must specify object name')
                self.help()
                return
            if args[1] not in globals():
                if len(args) == 3:
                    try:
                        modpath = os.path.dirname(args[2])
                        modname = os.path.basename(args[2])
                        if modpath != "": 
                            if modpath[0] == '/':
                                sys.path.insert(0, modpath)
                            else:
                                sys.path.insert(0, os.path.join(os.getcwd(), 
                                            modpath))
                        mod  = importlib.import_module(modname)
                        importlib.reload(mod)
                        if args[1] in dir(mod):
                            self.pt.ptchunk_callback = getattr(mod, args[1])
                            self.pt.ptchunk_callback_cached = None
                    except Exception as e:
                        self.pt.logmsg("[!] Couldn't load module: %s" % args[2])
                        print(e)
                else:
                    self.pt.logmsg("[!] Couldn't find object %s. Specify module" % 
                            args[1])
                    self.help()
            else:
                self.pt.ptchunk_callback = globals()[args[1]]
                self.pt.ptchunk_callback_cached = None
            self.pt.logmsg('%s registered as callback' % args[1])
        else:
            self.help()

################################################################################
class ptchunk(ptcmd):
    "print a comprehensive view of a ptchunk"

    def __init__(self, pt):
        super(ptchunk, self).__init__(pt, "ptchunk")

    def help(self):
        self.pt.logmsg('usage: ptchunk [-v] [-f] [-x] [-p offset] [-c <count>] [-s <val] [--depth <depth>] <addr>')
        self.pt.logmsg(' -v      use verbose output (multiples for more verbosity)')
        self.pt.logmsg(' -f      use <addr> explicitly, rather than be smart')
        self.pt.logmsg(' -x      hexdump the chunk contents')
        self.pt.logmsg(' -m      max bytes to dump with -x')
        self.pt.logmsg(' -c      number of chunks to print')
        self.pt.logmsg(' -s      search pattern when print chunks')
        self.pt.logmsg(' --depth how far into each chunk to search')
        self.pt.logmsg(' -d      debug and force printing stuff')
        self.pt.logmsg(' -n      do not output the trailing newline (summary representation)')
        self.pt.logmsg(' -p      print data inside at given offset (summary representation)')
        self.pt.logmsg(' <addr>  a ptmalloc chunk header')
        self.pt.logmsg('Flag legend: P=PREV_INUSE, M=MMAPPED, N=NON_MAIN_ARENA')
        return

    def invoke(self, arg, from_tty):
        try:
            self.invoke_(arg, from_tty)
        except Exception:
            h.show_last_exception()

    @hgdb.has_inferior
    def invoke_(self, arg, from_tty):
        "Usage can be obtained via ptchunk -h"
        if arg == '':
            self.help()
            return

        verbose = 0
        force = False
        hexdump = False
        no_newline = False
        maxbytes = 0

        c_found = False
        m_found = False
        s_found = False
        p_found = False
        search_val = None
        search_depth = 0
        depth_found = False
        debug = False
        count_ = 1
        print_offset = None
        addresses = []
        for item in arg.split():
            if m_found:
                if item.find("0x") != -1:
                    maxbytes = int(item, 16)
                else:
                    maxbytes = int(item)
                m_found = False
            if c_found:
                count_ = int(item)
                c_found = False
            elif p_found:
                try:
                    print_offset = int(item)
                except ValueError:
                    print_offset = int(item, 16)
                p_found = False
            elif item.find("-v") != -1:
                verbose += 1
            elif item.find("-f") != -1:
                force = True
            elif item.find("-n") != -1:
                no_newline = True
            elif item.find("-x") != -1:
                hexdump = True
            elif item.find("-m") != -1:
                m_found = True
            elif item.find("-c") != -1:
                c_found = True
            elif item.find("-p") != -1:
                p_found = True
            elif s_found:
                if item.find("0x") != -1:
                    search_val = item
                s_found = False
            elif depth_found:
                if item.find("0x") != -1:
                    search_depth = int(item, 16)
                else:
                    search_depth = int(item)
                depth_found = False
            # XXX Probably make this a helper
            elif item.find("0x") != -1:
                if item.find("-") != -1 or item.find("+") != -1:
                    addr = self.parse_var(item)
                else:
                    try:
                        addr = int(item, 16)
                    except ValueError:
                        addr = self.parse_var(item)
                addresses.append(addr)
            elif item.find("-s") != -1:
                s_found = True
            elif item.find("--depth") != -1:
                depth_found = True 

            elif item.find("$") != -1:
                addr = self.parse_var(item)
                addresses.append(addr)
            elif item.find("-d") != -1:
                debug = True # This is an undocumented dev option
            elif item.find("-h") != -1:
                self.help()
                return

        if not addresses or None in addresses:
            self.pt.logmsg("WARNING: No address supplied?")
            self.help()
            return

        bFirst = True
        for addr in addresses:
            if bFirst:
                bFirst = False
            else:
                print("-"*60)
            count = count_
            p = pt_chunk(self.pt, addr)
            if p.initOK == False:
                return
            dump_offset = 0
            while True:
                suffix = ""
                if search_val != None:
                    # Don't print if the chunk doesn't have the pattern
                    if not self.pt.search_chunk(p, search_val, 
                            depth=search_depth):
                        suffix += " [NO MATCH]"
                    else:
                        suffix += " [MATCH]"
                # XXX - the current representation is not really generic as we print the first short
                # as an ID and the second 2 bytes as 2 characters. We may want to support passing the
                # format string as an argument but this is already useful
                if print_offset != None:
                    mem = hgdb.get_inferior().read_memory(p.data_address + print_offset, 4)
                    (id_, desc) = struct.unpack_from("<H2s", mem, 0x0)
                    if h.is_ascii(desc):
                        suffix += " 0x%04x %s" % (id_, str(desc, encoding="utf-8"))
                    else:
                        suffix += " 0x%04x hex(%s)" % (id_, str(binascii.hexlify(desc), encoding="utf-8"))

                if verbose == 0:
                    if no_newline:
                        print(self.pt.chunk_info(p) + suffix, end="")
                    else:
                        print(self.pt.chunk_info(p) + suffix)
                elif verbose == 1:
                    print(p)
                    if self.pt.ptchunk_callback != None:
                        size = self.pt.chunksize(p) - p.hdr_size
                        if p.data_address != None:
                            # We can provide an excess of information and the
                            # callback can choose what to use
                            cbinfo = {}
                            # XXX - Don't know if we need to send all this
                            cbinfo["caller"] = "ptchunk"
                            cbinfo["allocator"] = "ptmalloc"
                            cbinfo["addr"] = p.data_address
                            cbinfo["hdr_sz"] = p.hdr_size
                            cbinfo["chunksz"] = self.pt.chunksize(p)
                            cbinfo["min_hdr_sz"] = self.pt.INUSE_HDR_SZ
                            cbinfo["data_size"] = size
                            cbinfo["inuse"] = p.inuse
                            cbinfo["size_sz"] = self.pt.SIZE_SZ
                            if debug:
                                cbinfo["debug"] = True
                                print(cbinfo)
                            # We expect callback to tell us how much data it
                            # 'consumed' in printing out info
                            dump_offset = self.pt.ptchunk_callback(cbinfo)
                        # mem-based callbacks not yet supported
                if hexdump:
                    self.pt.print_hexdump(p, maxbytes, dump_offset)
                count -= 1
                if count != 0:
                    if verbose == 1 or hexdump:
                        print('--')
                    p = pt_chunk(self.pt, addr=(p.address + self.pt.chunksize(p)))
                    if p.initOK == False:
                        break
                else:
                    break

################################################################################
class ptarena(ptcmd):
    "print a comprehensive view of an mstate which is representing an arena"

    def __init__(self, pt):
        super(ptarena, self).__init__(pt, "ptarena")

    def help(self):
        self.pt.logmsg('usage: ptarena [-v] [-f] [-x] [-c <count>] <addr>')
        self.pt.logmsg(' <addr> a ptmalloc mstate struct. Optional with cached mstate')
        self.pt.logmsg(' -v     use verbose output (multiples for more verbosity)')
        self.pt.logmsg(' -l     list arenas only')
        self.pt.logmsg(' NOTE: Last defined mstate will be cached for future use')
        return

    @hgdb.has_inferior
    def list_arenas(self, arena_address=None):
        if arena_address == None:
            if self.pt.pt_cached_mstate == None:
                self.pt.logmsg("WARNING: No cached arena")

                try:
                    main_arena = gdb.selected_frame().read_var('main_arena')
                    arena_address = main_arena.address
                except RuntimeError:
                    self.pt.logmsg("No gdb frame is currently selected.")
                    return
                except ValueError:
                    try:
                        res = gdb.execute('x/x &main_arena', to_string=True)
                        arena_address = int(res.strip().split()[0], 16)
                    except gdb.error:
                        self.pt.logmsg("WARNING: Debug glibc was not found.")
                        return

                        # XXX - we don't support that yet 

                        self.pt.logmsg("Guessing main_arena address via offset from libc.")

                        #find heap by offset from end of libc in /proc
                        # XXX - need to test this inferior call
                        libc_end,heap_begin = read_proc_maps(inferior.pid)

                        if self.pt.SIZE_SZ == 4:
                            #__malloc_initialize_hook + 0x20
                            #offset seems to be +0x380 on debug glibc,
                            #+0x3a0 otherwise
                            arena_address = libc_end + 0x3a0
                        elif self.pt.SIZE_SZ == 8:
                            #offset seems to be +0xe80 on debug glibc,
                            #+0xea0 otherwise
                            self.pt.arena_address = libc_end + 0xea0

                        if libc_end == -1:
                            self.pt.logmsg("Invalid address read via /proc")
                            return

            else:
                self.pt.logmsg("Using cached mstate")
                ar_ptr = self.pt.pt_cached_mstate
        else:    
            if arena_address == 0 or arena_address == None:
                self.pt.logmsg("Invalid arena address (0)")
                return
            ar_ptr = pt_arena(self.pt, arena_address)

        if ar_ptr.next == 0:
            self.pt.logmsg("No arenas could be correctly guessed.")
            self.pt.logmsg("Nothing was found at {0:#x}".format(ar_ptr.address))
            return

        print("Arena(s) found:")
        try:
            #arena address obtained via read_var
            print("\t arena @ {:#x}".format(
                    int(ar_ptr.address.cast(gdb.lookup_type("unsigned long")))))
        except Exception:
            #arena address obtained via -a
            print("\t arena @ {:#x}".format(int(ar_ptr.address)))

        if ar_ptr.address != ar_ptr.next:
            #we have more than one arena

            curr_arena = pt_arena(self.pt, ar_ptr.next)
            while (ar_ptr.address != curr_arena.address):
                print("\t arena @ {:#x}".format(int(curr_arena.address)))
                curr_arena = pt_arena(self.pt, curr_arena.next)

                if curr_arena.address == 0:
                    print("No arenas could be correctly found.")
                    break #breaking infinite loop

    def invoke(self, arg, from_tty):
        try:
            self.invoke_(arg, from_tty)
        except Exception:
            h.show_last_exception()


    @hgdb.has_inferior
    def invoke_(self, arg, from_tty):

        if self.pt.pt_cached_mstate == None and (arg == None or arg == ''):
            self.pt.logmsg("Neither arena cached nor argument specified")
            self.help()
            return

        verbose = 0
        list_only = False
        p = None
        if arg != None:
            for item in arg.split():
                if item.find("-v") != -1:
                    verbose += 1
                if item.find("-l") != -1:
                    list_only = True
                elif item.find("0x") != -1:
                    p = int(item, 16)
                elif item.find("$") != -1:
                    p = self.parse_var(item)
                elif item.find("-h") != -1:
                    self.help()
                    return

        if list_only:
            self.list_arenas(p)
            return

        if p == None and self.pt.pt_cached_mstate == None:
            self.pt.logmsg("WARNING: No address supplied?")
            self.help()
            return

        if p != None:
            p = pt_arena(self.pt, p)
            self.pt.logmsg("Caching mstate")
            self.pt.pt_cached_mstate = p
        else:
            self.pt.logmsg("Using cached mstate")
            p = self.pt.pt_cached_mstate

        if verbose == 0:
            print(p)
        elif verbose == 1:
            print(p)

############################################################################
# XXX - quite slow. Filter by arena or allow that we give it a starting address
class ptsearch(ptcmd):
    def __init__(self, pt):
        super(ptsearch, self).__init__(pt, "ptsearch")

    def help(self):
        print('[libptmalloc] usage: ptsearch -a <arena> <hex> <min_size> <max_size>')

    def invoke(self, arg, from_tty):
        try:
            self.invoke_(arg, from_tty)
        except Exception:
            h.show_last_exception()

    def invoke_(self, arg, from_tty):
        if arg == '':
            self.help()
            return
        arg = arg.split()
        #if arg[0].find("0x") == -1 or (len(arg[0]) != 10 and len(arg[0]) != 18):
        #    self.pt.logmsg("you need to provide a word or giant word for hex")
        #    return
        search_for = arg[0]
        if len(arg) > 3:
            self.help()
            return
        if len(arg) >= 2:
            max_size = int(arg[1], 16)
        else:
            max_size = 0
        if len(arg) == 3:
            min_size = int(arg[1], 16)
        else:
            min_size = 0

        if self.pt.pt_cached_mstate == None:
            print("ERROR: Cache an arena address using ptarena")
            return
        ar_ptr = self.pt.pt_cached_mstate
        arena_address = ar_ptr.address

        # we skip the main arena as it is in .data
        ar_ptr = ar_ptr.next

        while ar_ptr != arena_address:
            self.pt.logmsg("Handling arena @ 0x%x" % pt_arena(self.pt, ar_ptr).address)

            results = self.pt.search_heap(ar_ptr, search_for, min_size,
                                            max_size)

            if len(results) == 0:
                print('[libptmalloc] value %s not found' % (search_for))
                return

            for result in results:
                self.pt.logmsg("%s found in chunk at 0x%lx" % (search_for, int(result)))

            ar_ptr = pt_arena(self.pt, ar_ptr).next

################################################################################
class ptbin(ptcmd):
    "dump the layout of a free bin"

    def __init__(self, pt):
        super(ptbin, self).__init__(pt, "ptbin")

    def invoke(self, arg, from_tty):
        "Specify an optional arena addr: ptbin main_arena=0x12345"

        if len(arg) == 0:
            print_error("Please specify the free bin to dump")
            return

        try:
            if arg.find("main_arena") == -1:
                main_arena = gdb.selected_frame().read_var('main_arena')
                main_arena_address = main_arena.address
            else:
                arg = arg.split()
                for item in arg:
                    if item.find("main_arena") != -1:
                        if len(item) < 12:
                            print_error("Malformed main_arena parameter")
                            return
                        else:
                            main_arena_address = int(item[11:],16)
        except RuntimeError:
            print_error("No frame is currently selected.")
            return
        except ValueError:
            print_error("Debug glibc was not found.")
            return

        if main_arena_address == 0:
            print_error("Invalid main_arena address (0)")
            return

        ar_ptr = pt_arena(self.pt, main_arena_address)
        hgdb.mutex_lock(ar_ptr)

        print_title("Bin Layout")

        b = self.pt.bin_at(ar_ptr, int(arg))
        p = pt_chunk(self.pt, self.pt.first(pt_chunk(b, inuse=False)), inuse=False)
        print_once = True
        print_str  = ""
        count      = 0

        while p.address != int(b):
            if print_once:
                print_once=False
                print_str += "-->  "
                print_str += color_value("[bin {}]".format(int(arg)))
                count += 1

            print_str += "  <-->  "
            print_str += color_value("{:#x}".format(int(p.address)))
            count += 1
            p = pt_chunk(self.pt, self.pt.first(p), inuse=False)

        if len(print_str) != 0:
            print_str += "  <--"
            print(print_str)
            print("|{}|".format(" " * (len(print_str) - 2 - count*12)))
            print("{}".format("-" * (len(print_str) - count*12)))
        else:
            print("Bin {} empty.".format(int(arg)))

        hgdb.mutex_unlock(ar_ptr)

################################################################################
def get_arenas(pt):
    try:
        arenas = []
        bin_name = hgdb.get_info()
        log = logger()

        if pt.pt_cached_mstate == None:
            log.logmsg("WARNING: Need cached main_arena. Use ptarena first.")
            return
        main_arena = pt.pt_cached_mstate.address

        res = gdb.execute("ptarena -l 0x%x" % main_arena, to_string=True)
        res = res.split("\n")
        # format is: ['Arena(s) found:', '\t arena @ 0x7ffff4c9b620', '\t arena @ 0x7fffa4000020', ... ]
        for line in res:
            result = re.match("\t arena @ (.*)", line)
            if result:
                arenas.append(int(result.group(1), 16))
        arenas.sort()
        return arenas
    except Exception as e:
        h.show_last_exception()  


# infile.txt needs to contains something like:
#0x7fffc03cc650
#0x7fffb440cae0
#0x7fffb440c5e0
# XXX - we could just save all arenas when doing ptarena -l in the first place
arenas = None
class ptarenaof(ptcmd):

    def __init__(self, pt):
        super(ptarenaof, self).__init__(pt, "ptarenaof")

    def help(self):
        self.logmsg('usage: ptarenaof <addr>|<infile.txt>')
        self.logmsg(' <addr>  a ptmalloc chunk header')
        self.logmsg(' <infile.txt> a filename for a file containing one ptmalloc chunk header address per line')
        return
    
    def invoke(self, arg, from_tty):
        global arenas
        try:
            if arg == '' or arg == "-h":
                self.help()
                return
            
            if self.pt.pt_cached_mstate == None:
                self.logmsg("WARNING: Need cached main_arena. Use ptarena first.")
                self.help()
                return
        
            arg = arg.split()
            try:
                addresses = [int(arg[0], 16)]
            except ValueError:
                self.logmsg("Reading from file: %s" % arg[0])
                fd = open(arg[0], "r")
                addresses = [int(l[:-1], 16) for l in fd]

            if not arenas:
                self.logmsg("Loading arenas")
                arenas = get_arenas(self.pt)
                #self.logmsg("Found arenas: " + "".join(["0x%x, " % a for a in arenas]))

            addr_seen = set([])
            for addr in addresses:
                ar = addr & 0xffffffffff000000
                ar += 0x20
                if ar not in arenas:
                    #self.logmsg("Warning: arena not found for 0x%x, finding closest candidate" % addr)
                    # we previously sorted arenas so we can easily find it
                    bFound = False
                    for i in range(len(arenas)-1):
                        if ar >= arenas[i] and ar < arenas[i+1]:
                            ar = arenas[i]
                            bFound = True
                            break
                    if not bFound:
                        if ar > arenas[-1]:
                            ar = arenas[-1]
                        else:
                            self.logmsg("Could not find arena for 0x%x, skipping" % addr)
                            continue
                if ar not in addr_seen:
                    #self.logmsg("arena: 0x%x" % ar)
                    addr_seen.add(ar)
            if addr_seen:
                self.logmsg("Seen arenas: " + "".join(["0x%x," % a for a in sorted(list(addr_seen))]))
        except Exception as e:
            h.show_last_exception()   


################################################################################
# E.g. usage:
#(gdb) ptscanchunks 0x7fffb4000020,0x7fffbc000020
class ptscanchunks(ptcmd):

    def __init__(self, pt):
        super(ptscanchunks, self).__init__(pt, "ptscanchunks")

    def help(self):
        self.logmsg('usage: ptscanchunks [<addr_list>')
        self.logmsg(' <addr>  comma separated list of arena addresses')
        return
    
    def invoke(self, arg, from_tty):
        try:
            if arg == '':
                self.help()
                return

            arg = arg.split(",")
            if arg[-1] == "":
                arg = arg[:-1]

            for ar in arg:
                addr = int(ar, 16)
                # XXX - fix that empirically first chunk is NOT always at 0x8b0
                addr = addr & 0xffffffffff000000
                addr += 0x8b0
                self.logmsg("Scanning 0x%x ..." % addr)
                res = gdb.execute("ptchunk 0x%x -c 1000000" % addr, to_string=False)

        except Exception as e:
            h.show_last_exception()

################################################################################
class pthelp(ptcmd):
    "Details about all libptmalloc gdb commands"

    def __init__(self, pt, help_extra=None):
        self.help_extra = help_extra
        super(pthelp, self).__init__(pt, "pthelp")

    def invoke(self, arg, from_tty):
        self.pt.logmsg('ptmalloc commands for gdb')
        if self.help_extra != None:
            self.pt.logmsg(self.help_extra)
        self.pt.logmsg('ptchunk      : show chunk contents (-v for verbose, -x for data dump)')
        self.pt.logmsg('ptsearch     : search heap for hex value or address')
        self.pt.logmsg('ptarena      : print mstate struct. caches address after first use')
        self.pt.logmsg('ptcallback   : print mstate struct. caches address after first use')
        self.pt.logmsg('ptarenaof    : print arena for a given chunk or a list of chunks')
        self.pt.logmsg('ptscanchunks : print all chunks for all provided arenas')
        self.pt.logmsg('pthelp     : this help message')
        self.pt.logmsg('NOTE: Pass -h to any of these commands for more extensive usage. Eg: ptchunk -h')

if __name__ == "__main__":
    pth = pt_helper()

    pthelp(pth)
    ptcallback(pth)
    ptchunk(pth)
    ptarena(pth)
    ptsearch(pth)
    ptstats(pth)
    ptbin(pth)
    ptarenaof(pth)
    ptscanchunks(pth)
    pth.logmsg("loaded")

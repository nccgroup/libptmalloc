# -*- coding: future_fstrings -*-
import struct
import sys
import hexdump
import logging

from libptmalloc.ptmalloc import tcache_perthread as tp
from libptmalloc.ptmalloc import malloc_chunk as mc
from libptmalloc.ptmalloc import malloc_state as ms
from libptmalloc.ptmalloc import malloc_par as mp

log = logging.getLogger("libptmalloc")
log.trace("cache.py")

class cache:
    """Hold cached information such as objects representing ptmalloc structures, 
    as well as chunk's addresses in the respective bins.
    
    Since browsing all these big structures and arrays can be slow in gdb, we cache
    them in this object."""

    def __init__(self, ptm):
        self.ptm = ptm

        # Assume we can re-use known mstate when not specified
        self.main_arena_address = None
        self.mstate = None # latest cached arena i.e. malloc_mstate object used in all future commands
        self.par = None # latest cached parameters i.e. malloc_par object
        self.tcache = None # latest cached tcache i.e. tcache_perthread object

        # Arrays of arrays holding the addresses of all the chunks in the respective bins
        self.bins = None # even though we don't technically need to keep track of freed chunks 
                         # in unsorted/small/large bins to print chunks types with "ptchunk", it
                         # is still handy to cache them when printing chunks in bins, hence why
                         # we track them
        self.fast_bins = None
        self.tcache_bins = None

    def update_tcache(self, address=None, show_status=False, use_cache=False):
        """Update the tcache_perthread object
        
        :param address: tcache's name or address if don't want to use the cached or default one
        """

        log.debug("cache.update_tcache()")
        
        if not self.ptm.is_tcache_enabled() or not self.ptm.tcache_available:
            return # nothing to be done if tcache disabled

        if address != None and address < 1024:
            raise Exception(f"Wrong tcache address: {address}?")

        if address != None:
            if show_status:
                print(f"Caching tcache @ {address:#x}")
            self.tcache = tp.tcache_perthread(self.ptm, address, debugger=self.ptm.dbg, version=self.ptm.version)
            if not self.tcache.initOK:
                raise Exception("Wrong tcache address?")
        elif self.tcache != None:
            if use_cache:
                if show_status:
                    print("Using cached tcache")
            else:
                if show_status:
                    print("Retrieving tcache again")
                tcache_address = self.tcache.address
                self.tcache = None # enforce retrieving it again below
        else:
            tcache_address = self.ptm.dbg.read_variable("tcache")
            if show_status:
                print(f"Caching global 'tcache' @ {int(tcache_address):#x}")
        
        if self.tcache == None:
            self.tcache = tp.tcache_perthread(self.ptm, tcache_address, debugger=self.ptm.dbg, version=self.ptm.version)

    def update_param(self, address=None, show_status=False, use_cache=False, invalid_ok=False):
        """Update the malloc_param object
        
        :param address: param's name or address if don't want to use the cached or default one
        """

        log.debug("cache.update_param()")

        if address != None and address < 1024:
            raise Exception(f"Wrong mp address: {address}?")

        if address != None:
            if show_status:
                print(f"Caching malloc parameters @ {address:#x}")
            self.par = mp.malloc_par(self.ptm, address, debugger=self.ptm.dbg, version=self.ptm.version, invalid_ok=invalid_ok)
            if not self.par.initOK:
                raise Exception("Wrong mp address?")
        elif self.par != None:
            if use_cache:
                if show_status:
                    print("Using cached malloc parameters")
            else:
                if show_status:
                    print("Retrieving malloc parameters again")
                mp_address = self.par.address
                self.par = None # enforce retrieving it again below
        else:
            mp_ = self.ptm.dbg.read_variable_address("mp_")
            log.debug(f"mp = {mp_}")
            mp_address = self.ptm.dbg.format_address(mp_)
            log.debug(f"mp_address = {mp_address:#x}")
            if show_status:
                print(f"Caching global 'mp_' @ {mp_address:#x}")
        
        if self.par == None:
            self.par = mp.malloc_par(self.ptm, mp_address, debugger=self.ptm.dbg, version=self.ptm.version, invalid_ok=invalid_ok)

    def update_arena(self, address=None, show_status=False, use_cache=False):
        """Update the malloc_state object
        
        :param address: arena's name or address if don't want to use the cached or default one
        """

        log.debug("cache.update_arena()")

        # XXX - also support thread_arena somehow, see libheap?
        # XXX - &main_arena == thread_arena?

        if address != None and address < 1024:
            raise Exception(f"Wrong arena address: {address}?")

        # The main arena address should never change so don't need 
        # to retrieve it more than once (it stays in cache)
        if self.main_arena_address == None:
            if show_status:
                print("Retrieving 'main_arena'")
            main_arena = self.ptm.dbg.read_variable_address("main_arena")
            log.debug(f"main_arena = {main_arena}")
            main_arena_address = self.ptm.dbg.format_address(main_arena)
            log.debug(f"main_arena_address = {main_arena_address}")
            self.main_arena_address = main_arena_address

        if address != None:
            if show_status:
                print(f"Caching arena @ {address:#x}")
            self.mstate = ms.malloc_state(self.ptm, address, debugger=self.ptm.dbg, version=self.ptm.version)
            if not self.mstate.initOK:
                raise Exception("Wrong arena address?")
        elif self.mstate != None:
            if use_cache:
                if show_status:
                    print("Using cached arena")
            else:
                if show_status:
                    print("Retrieving arena again")
                mstate_address = self.mstate.address
                self.mstate = None # enforce retrieving it again below
        else:
            mstate_address = self.main_arena_address
            if show_status:
                print(f"Caching global 'main_arena' @ {mstate_address:#x}")
        
        if self.mstate == None:
            self.mstate = ms.malloc_state(self.ptm, mstate_address, debugger=self.ptm.dbg, version=self.ptm.version)

        # arena_address = self.ptm.dbg.read_variable_address("main_arena")
        # thread_arena = self.ptm.dbg.read_variable("thread_arena")
        # if thread_arena is not None:
        #     thread_arena_address = self.ptm.dbg.format_address(thread_arena)
        # else:
        #     thread_arena_address = arena_address

        # if address != None:
        #     arena_address = address
        # else:
        #     arena_address = thread_arena_address

    def update_bins(self, show_status=False, use_cache=False, bins_list=[]):
        """Fetches the chunks' addresses in the malloc_state.bins[] array
        and cache the information for future use

        :param bins_list: If non-empty, contains a list of indexes into the bin array
                           that we update. It means the others won't be modified. It
                           serves as an optimization so we can update only certain bins
        """

        log.debug("cache.update_bins()")

        if self.bins != None:
            if use_cache:
                if show_status:
                    print("Using cached unsorted/small/large bins")
                return
            else:
                if show_status:
                    print("Retrieving unsorted/small/large bins again")
                    self.bins = None
        else:
            if show_status:
                print("Retrieving unsorted/small/large bins")

        ptm = self.ptm
        dbg = self.ptm.dbg

        bins = []
        for index in range(0, ptm.NBINS-1):
            if self.bins != None and bins_list and index not in bins_list:
                bins.append(self.bins[index])
            else:
                bins.append(self.get_bin_chunks(index))

        # Only update if no error to avoid caching incomplete info
        self.bins = bins

    def get_bin_chunks(self, index):
        """Fetches the chunks' addresses in the malloc_state.bins[] array
        for the specified index

        :return: the list of addresses in this specified bin
        """

        log.debug("get_bin_chunks(%d)" % index)
        ptm = self.ptm
        mstate = ptm.cache.mstate
        dbg = self.ptm.dbg

        #ptm.mutex_lock(mstate)

        b = ptm.bin_at(mstate, index+1)
        if b == 0:      # Not initialized yet
            return []

        p = mc.malloc_chunk(
            ptm, 
            b, 
            inuse=False, 
            debugger=dbg,
            tcache=False,
            fast=False,
            allow_invalid=True)

        addresses = []
        while p.fd != int(b):
            addresses.append(p.address)
            p = mc.malloc_chunk(
                ptm, 
                ptm.first(p), 
                inuse=False, 
                debugger=dbg,
                tcache=False,
                fast=False,
                allow_invalid=True)

        #ptm.mutex_unlock(mstate)

        return addresses

    def update_fast_bins(self, show_status=False, use_cache=False, bins_list=[]):
        """Fetches the chunks' addresses in the malloc_state.fastbinsY[] array
        and cache the information for future use

        :param bins_list: If non-empty, contains a list of indexes into the bin array
                           that we update. It means the others won't be modified. It
                           serves as an optimization so we can update only certain bins
        """

        log.debug("cache.update_fast_bins()")

        if self.fast_bins != None:
            if use_cache:
                if show_status:
                    print("Using cached fast bins")
                return
            else:
                if show_status:
                    print("Retrieving fast bins again")
                    self.fast_bins = None
        else:
            if show_status:
                print("Retrieving fast bins")

        ptm = self.ptm
        dbg = self.ptm.dbg

        fast_bins = []
        for index in range(0, ptm.NFASTBINS):
            if self.fast_bins != None and bins_list and index not in bins_list:
                fast_bins.append(self.fast_bins[index])
            else:
                fast_bins.append(self.get_fast_bin_chunks(index))

        # Only update if no error to avoid caching incomplete info
        self.fast_bins = fast_bins

    def get_fast_bin_chunks(self, index):
        """Fetches the chunks' addresses in the malloc_state.fastbinsY[] array
        for the specified index

        :return: the list of addresses in this specified bin
        """

        ptm = self.ptm
        mstate = ptm.cache.mstate
        dbg = self.ptm.dbg

        fb_base = int(mstate.address) + mstate.fastbins_offset

        p = mc.malloc_chunk(
            ptm,
            addr=fb_base - (2 * ptm.SIZE_SZ) + index * ptm.SIZE_SZ,
            fast=True,
            debugger=dbg,
            allow_invalid=True,
        )

        addresses = []
        while p.fd != 0:
            if p.fd is None:
                break
            addresses.append(p.fd)
            p = mc.malloc_chunk(
                ptm, 
                p.fd, 
                fast=True,
                debugger=dbg,
                allow_invalid=True,
            )
        
        return addresses

    def update_tcache_bins(self, show_status=False, use_cache=False, bins_list=[]):
        """Fetches the chunks' addresses in the tcache_perthread_struct.entries[] array
        and cache the information for future use

        :param bins_list: If non-empty, contains a list of indexes into the bin array
                           that we update. It means the others won't be modified. It
                           serves as an optimization so we can update only certain bins
        """

        log.debug("cache.update_tcache_bins()")

        if not self.ptm.is_tcache_enabled() or not self.ptm.tcache_available:
            return # nothing to be done if tcache disabled

        if self.tcache_bins != None:
            if use_cache:
                if show_status:
                    print("Using cached tcache bins")
                return
            else:
                if show_status:
                    print("Retrieving tcache bins again")
                    self.tcache_bins = None
        else:
            if show_status:
                print("Retrieving tcache bins")

        ptm = self.ptm
        dbg = self.ptm.dbg

        tcache_bins = []
        for index in range(0, ptm.TCACHE_MAX_BINS):
            if self.tcache_bins != None and bins_list and index not in bins_list:
                tcache_bins.append(self.tcache_bins[index])
            else:
                tcache_bins.append(self.get_tcache_bin_chunks(index))

        # Only update if no error to avoid caching incomplete info
        self.tcache_bins = tcache_bins

    def get_tcache_bin_chunks(self, index):
        """Fetches the chunks' addresses in the tcache_perthread_struct.entries[] array
        for the specified index

        :return: the list of addresses in this specified bin
        """

        ptm = self.ptm
        tcache = ptm.cache.tcache
        dbg = self.ptm.dbg

        if tcache.entries[index] == 0:
            return []
        # I've seen uninitialized entries[] still holding old data i.e. non-null
        # even though the counts is 0
        if tcache.counts[index] == 0:
            return []

        addr = tcache.entries[index] - 2 * ptm.SIZE_SZ
        p = mc.malloc_chunk(ptm, addr, inuse=False, debugger=dbg, allow_invalid=True, tcache=True)
        if not p.initOK: # afaict should not happen in a normal scenario but better be safe
            return []

        addresses = []
        while True:
            addresses.append(p.address)
            if p.next == 0x0:
                break
            addr = p.next - 2 * ptm.SIZE_SZ
            p = mc.malloc_chunk(ptm, addr, inuse=False, debugger=dbg, allow_invalid=True, tcache=True)
            if not p.initOK: # same
                return addresses
        
        return addresses
    
    def update_all(self, show_status=False, use_cache=False, arena_address=None):
        self.update_arena(address=arena_address, show_status=show_status, use_cache=use_cache)
        self.update_param(show_status=show_status, use_cache=use_cache)
        self.update_tcache(show_status=show_status, use_cache=use_cache)

        self.update_fast_bins(show_status=show_status, use_cache=use_cache)
        self.update_tcache_bins(show_status=show_status, use_cache=use_cache)

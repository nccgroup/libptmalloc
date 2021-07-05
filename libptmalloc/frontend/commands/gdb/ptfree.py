from __future__ import print_function

import argparse
import struct
import sys
import logging
import importlib

import libptmalloc.frontend.printutils as pu
importlib.reload(pu)
import libptmalloc.ptmalloc.malloc_chunk as mc
importlib.reload(mc)
import libptmalloc.ptmalloc.malloc_state as ms
importlib.reload(ms)
import libptmalloc.ptmalloc.ptmalloc as pt
importlib.reload(pt)
import libptmalloc.frontend.helpers as h
importlib.reload(h)
import libptmalloc.frontend.commands.gdb.ptchunk as ptchunk
importlib.reload(ptchunk)
import libptmalloc.frontend.commands.gdb.ptcmd as ptcmd # no reload on purpose

log = logging.getLogger("libptmalloc")
log.trace("ptfree.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")

class ptfree(ptcmd.ptcmd):
    """Command to walk and print all bins

    Also see ptchunk description"""

    def __init__(self, ptm):
        log.debug("ptfree.__init__()")
        super(ptfree, self).__init__(ptm, "ptfree")

        self.parser = argparse.ArgumentParser(
            description="""Print all bins information

Browse fast bins, tcache bins, unsorted/small/large bins.
Effectively calls into 'ptfast', 'pttcache' and 'ptbin' commands""", 
            formatter_class=argparse.RawTextHelpFormatter,
            add_help=False)
        # "ptchunk" also has this argument but default and help is different
        self.parser.add_argument(
            "-c", "--count", dest="count", type=h.check_positive, default=None,
            help="Maximum number of chunks to print in each bin"
        )
        # other arguments are implemented in the "ptchunk" command
        # and will be shown after the above
        ptchunk.ptchunk.add_arguments(self)

    @h.catch_exceptions
    @ptcmd.ptcmd.init_and_cleanup
    def invoke(self, arg, from_tty):
        """Inherited from gdb.Command
        See https://sourceware.org/gdb/current/onlinedocs/gdb/Commands-In-Python.html
        """

        log.debug("ptfree.invoke()")

        self.cache.update_arena(show_status=self.args.debug)
        mstate = self.cache.mstate

        self.cache.update_tcache(show_status=self.args.debug)
        # This is required by ptchunk.parse_many()
        self.cache.update_param(show_status=self.args.debug)

        # We don't update the tcache bins, fast bins and unsorted/small/large bins
        # in the cache because it will automatically be done in show_all_bins()
        # The idea is we'd rather have things written over time than fetching all the cache
        # at the beginning without having any output for the user
        self.show_all_bins(mstate)

    @staticmethod
    def bin_size2index(ptm, name, size):
        """Convert a chunk size into an index in one of the bin array:
        tcache.entries[], malloc.fastbinsY[] or malloc.bins[]
        
        :param ptm: ptmalloc object
        :param name: "tcache", "fast" or "regular" string
        :param size: the chunk size queried
        :return: the matching index in the corresponding array
        """

        if name == "tcache":
            return ptm.tcache_bin_index(size)
        elif name == "fast":
            return ptm.fast_bin_index(size)
        elif name == "regular":
            # XXX: -1 is because the index 0 is for unsorted bin?
            return ptm.bin_index(size)-1
        else:
            raise Exception("Wrong name in bin_size2index()")

    @staticmethod
    def update_bins_in_cache(ptm, 
        name, 
        show_status=False, 
        use_cache=False,
        bins_list=[]
    ):
        """Update the bins in the cache for one of the bin array:
        tcache.entries[], malloc.fastbinsY[] or malloc.bins[]
        
        :param ptm: ptmalloc object
        :param name: "tcache", "fast" or "regular" string
        :param show_status: True to print cache status, False to not print it
        :param use_cache: True to avoid fetching structures and bins. False to
                          fetch them again and update the cache
        :param bins_list: If non-empty, contains a list of indexes into the bin array
                           that we update. It means the others won't be modified. It
                           serves as an optimization so we can update only certain bins
        
        :return: the matching index in the corresponding array
        """

        if name == "tcache":
            ptm.cache.update_tcache_bins(show_status=show_status, use_cache=use_cache, bins_list=bins_list)
        elif name == "fast":
            ptm.cache.update_fast_bins(show_status=show_status, use_cache=use_cache, bins_list=bins_list)
        elif name == "regular":
            ptm.cache.update_bins(show_status=show_status, use_cache=use_cache, bins_list=bins_list)
        else:
            raise Exception("Wrong name in update_bins_in_cache()")

    @staticmethod
    def get_chunks_addresses_in_bin(ptm, 
        name,
        index
    ):
        """Get the list of chunks addresses in in one of the bin array:
        tcache.entries[], malloc.fastbinsY[] or malloc.bins[]
        for a given index
        
        :param ptm: ptmalloc object
        :param name: "tcache", "fast" or "regular" string
        :param index: the index in the particular bin
        :return: the list of chunks' addresses (list of integers)
        """

        if name == "tcache":
            return ptm.cache.tcache_bins[index]
        elif name == "fast":
            return ptm.cache.fast_bins[index]
        elif name == "regular":
            return ptm.cache.bins[index]
        else:
            raise Exception("Wrong name in get_chunks_addresses_in_bin()")

    @staticmethod
    def get_bin_header(ptm, 
        name,
        index,
        empty=False
    ):
        """Get the string header shown before printing a given bin array:
        tcache.entries[], malloc.fastbinsY[] or malloc.bins[]
        for a given index
        
        :param ptm: ptmalloc object
        :param name: "tcache", "fast" or "regular" string
        :param index: the index in the particular bin
        :param empty: True if the bin for that array and index does not have
                      any chunk.
        :return: the string to show before printing the actual chunks in a bin
        """

        if name == "tcache":
            header = pu.color_header("{} bin {}".format(name, index))
            header += " (sz {:#x})".format(ptm.tcache_bin_size(index))
        elif name == "fast":
            header = pu.color_header("{} bin {}".format(name, index))
            header += " (sz {:#x})".format(ptm.fast_bin_size(index))
        elif name == "regular":
            if index == ptm.bin_index_unsorted:
                header = pu.color_header("unsorted bin {}".format(index))
                header += " (various sz)"
            elif index <= ptm.bin_index_small_max:
                header = pu.color_header("small bin {}".format(index))
                header += " (sz {:#x})".format(ptm.bin_size(index))
            elif index <= ptm.bin_index_large_max:
                header = pu.color_header("large bin {}".format(index))
                header += " (sz {:#x})".format(ptm.bin_size(index))
            elif index == ptm.bin_index_uncategorized:
                header = pu.color_header("large bin uncategorized {}".format(index))
                header += " (sz > {:#x})".format(ptm.bin_size(127))
        else:
            raise Exception("Wrong name in get_bin_header()")
        if empty:
            header += " is empty"
        return header

    @staticmethod
    def get_bin_footer(self, 
        name,
        index,
        printed_count,
        max_count=None
    ):
        """Get the string footer shown after printing a given bin array:
        tcache.entries[], malloc.fastbinsY[] or malloc.bins[]
        for a given index
        
        :param self: ptfree object
        :param name: "tcache", "fast" or "regular" string
        :param index: the index in the particular bin
        :param printed_count: How many chunks were already printed for that bin
        :param max_count: How many chunks were requested to be printed by the user
                          or None if no limit.
        :return: the string to show after printing the actual chunks in a bin
        """

        if name == "tcache":
            footer = pu.color_footer("{} bin {}".format(name, index))
        elif name == "fast":
            footer = pu.color_footer("{} bin {}".format(name, index))
        elif name == "regular":
            if index == self.ptm.bin_index_unsorted:
                footer = pu.color_footer("unsorted bin {}".format(index))
            elif index <= self.ptm.bin_index_small_max:
                footer = pu.color_footer("small bin {}".format(index))
            elif index <= self.ptm.bin_index_large_max:
                footer = pu.color_footer("large bin {}".format(index))
            elif index == self.ptm.bin_index_uncategorized:
                footer = pu.color_footer("large uncategorized bin {}".format(index))
        else:
            raise Exception("Wrong name in get_bin_footer()")
        if max_count == None or printed_count < max_count:
            footer += f": total of {printed_count} chunks"
        else:
            footer += f": total of {printed_count}+ chunks"
        return footer

    @staticmethod
    def get_count_bins(ptm, name):
        """Retrieve how many bins there is for given bin array:
        tcache.entries[], malloc.fastbinsY[] or malloc.bins[]
        
        :param ptm: ptmalloc object
        :param name: "tcache", "fast" or "regular" string
        :return: the size of the bin array
        """

        if name == "tcache":
            return ptm.TCACHE_MAX_BINS
        elif name == "fast":
            return ptm.NFASTBINS
        elif name == "regular":
            return ptm.NBINS-1
        else:
            raise Exception("Wrong name in get_count_bins()")

    @staticmethod
    def show_one_bin(
        self,
        name,
        index=None, 
        size=None, 
        print_empty=True, 
        show_status=False, 
        use_cache=False,

    ):
        """Browse a given index for a given bin array:
        tcache.entries[], malloc.fastbinsY[] or malloc.bins[]
        and show the actual chunks in that particular bin

        :param ptm: ptmalloc object
        :param name: "tcache", "fast" or "regular" string
        :param index: the index in the particular bin (instead of size) or None
        :param size: the chunk size in the particular bin (instead of index) or None
        :param print_empty: True if we want to show empty bins. False otherwise
        :param show_status: True to print cache status, False to not print it
        :param use_cache: True to avoid fetching structures and bins. False to
                          fetch them again and update the cache

        Note that this function assumes self.args.real_count exists and equals
        to the number of chunks requested to be printed by the user (using -c i.e.
        initially equal to self.args.count).
        This is because show_one_bin() may be called several times but sometimes
        we need to override self.args.count to be equal to 1 before we can call into
        ptchunk.parse_many2(), but still passing the real_count as count_printed 
        argument

        Note that it is a static method but it has self as a first
        argument to make it easier to read its implementation
        """

        ptm = self.ptm
        dbg = self.dbg

        if index == None and size == None:
            raise Exception("show_one_bin requires an index or size")
        if size != None and index != None:
            raise Exception("show_one_bin requires either an index or a size, not both")
        if index == None:
            index = ptfree.bin_size2index(ptm, name, size)

        if index < 0 or index >= ptfree.get_count_bins(ptm, name):
            raise Exception("index out of range in bin")

        # Prepare arguments passed to malloc_chunk() for all the chunks
        # in the bin
        tcache = None
        fast = None
        inuse = None
        if name == "tcache":
            tcache = True
        elif name == "fast":
            fast = True
        elif name == "regular":
            inuse = False
            tcache = False
            fast = False
        else:
            raise Exception("Wrong name in show_one_bin()")
        
        ptfree.update_bins_in_cache(ptm, name, show_status=show_status, use_cache=use_cache, bins_list=[index])
        bin_ = [f"{addr:#x}" for addr in ptfree.get_chunks_addresses_in_bin(self, name, index)]

        if len(bin_) == 0:
            if print_empty:
                print(ptfree.get_bin_header(ptm, name, index, empty=True))
            return 0

        # Prepare arguments for "ptchunk" format
        # i.e. the chunks to print are from the bin
        # The amount of printed addresses will be limited by 
        # parse_many2()'s count_printed argument
        self.args.addresses = bin_
        self.args.no_newline = False
        # Quirk of parse_many2() since we only want to print 1 chunk linearly
        # in memory for every chunk in the bin and the real count of chunks is 
        # set above in self.args.addresses
        self.args.count = 1

        header_once = ptfree.get_bin_header(ptm, name, index)
        chunks = ptchunk.ptchunk.parse_many2(
            self,
            inuse=inuse,
            tcache=tcache,
            fast=fast,
            allow_invalid=True,
            separate_addresses_non_verbose=False,
            header_once=header_once,
            count_handle=1,
            count_printed=self.args.real_count
        )

        if print_empty or len(chunks) > 0:
            print(ptfree.get_bin_footer(self, name, index, len(chunks), self.args.real_count))

        return len(chunks)

    def show_all_bins(self, mstate):
        """Calls into pttcache, ptfast and ptbin to browse the bins and show how many chunk there is.
        It does not show the actual chunks in each bin though
        """
        
        ptm = self.ptm

        # As you can see below, we don't pass any use_cache=True because we want it to re-fetch
        # data, as pointed out in the comment above in invoke()

        # Save old count since we will override it later
        # when we call into ptchunk but we need to reset it
        # for every show_one_*() calls in the 3 loops below
        self.args.real_count = self.args.count

        if self.ptm.is_tcache_enabled() and self.ptm.tcache_available:
            for i in range(ptfree.get_count_bins(ptm, "tcache")):
                count = ptfree.show_one_bin(self, "tcache", index=i, print_empty=False)
                if count > 0:
                    print("---")

        for i in range(ptfree.get_count_bins(ptm, "fast")):
            count = ptfree.show_one_bin(self, "fast", index=i, print_empty=False)
            if count > 0:
                print("---")

        for i in range(ptfree.get_count_bins(ptm, "regular")):
            count = ptfree.show_one_bin(self, "regular", index=i, print_empty=False)
            if count > 0:
                print("---")
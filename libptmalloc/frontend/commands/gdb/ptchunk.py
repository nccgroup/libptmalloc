from __future__ import print_function

import argparse
import binascii
import struct
import sys
import logging
import importlib
import json
import os

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
import libptmalloc.frontend.commands.gdb.ptmeta as ptmeta
importlib.reload(ptmeta)
import libptmalloc.frontend.commands.gdb.ptcmd as ptcmd # no reload on purpose

log = logging.getLogger("libptmalloc")
log.trace("ptchunk.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")  

class ptchunk(ptcmd.ptcmd):
    """Command to print information about chunk(s) represented by the malloc_chunk structure
    
    There are a couple of quirks to know. The "ptlist" command shares lots of
    arguments and features with the "ptchunk" command. It would have make
    sense to inherit the "ptlist" class from the "ptchunk" class, however we 
    would have the same problem as with the "ptcmd" where we can't reload the 
    "ptchunk.py" file without restarting gdb. This would have been annoying so 
    work around that by having some methods of the "ptchunk" class defined as 
    static methods and we just call into these from the "ptlist" class
    This is less "clean" but eases a lot development.
    And similarly for the "pttcache", "ptbin" and "ptfast" commands.
    """

    search_types = ["string", "byte", "word", "dword", "qword"]

    def __init__(self, ptm):
        log.debug("ptchunk.__init__()")
        super(ptchunk, self).__init__(ptm, "ptchunk")

        self.parser = argparse.ArgumentParser(
            description="""Show one or more chunks' header and contents

Can provide you with a summary of a chunk (one-line) or more verbose information 
of every field (multiple lines). 
You can also list information of multiple chunks, search chunks, etc.
""", 
            add_help=False, 
            formatter_class=argparse.RawTextHelpFormatter,
            epilog="""E.g.
ptchunk mem-0x10 -v -x -M "tag, backtrace"
ptchunk mem-0x10 -M "backtrace:5"

Allocated/free flag: M=allocated, F=freed, f=fast, t=tcache
Flag legend: P=PREV_INUSE, M=MMAPPED, N=NON_MAIN_ARENA""")

        ptchunk.add_arguments(self)
    
    @staticmethod
    def add_arguments(self):
        """Most arguments are shared by "ptchunk" and "ptlist" commands.
        This function allows to initialize them in "ptlist" too
        
        E.g. if we created a "ptlist", we will add arguments later
        # after we create our own parser

        Note that it is a static method but it has self as a first
        argument to make it easier to read its implementation
        """
        if self.name == "ptchunk":
            group = self.parser
        else:
            group = self.parser.add_argument_group("generic optional arguments")
        if self.name == "ptchunk":
            self.parser.add_argument(
                "addresses", nargs="*", default=None,
                help="Address(es) to ptmalloc chunk headers"
            )
        group.add_argument(
            "-v", "--verbose", dest="verbose", action="count", default=0,
            help="Use verbose output (multiple for more verbosity)"
        )
        group.add_argument(
            "-h", "--help", dest="help", action="store_true", default=False,
            help="Show this help"
        )
        if self.name == "ptchunk":
            group.add_argument(
                "-c", "--count", dest="count", type=h.check_count_value, default=1,
                help="""Number of chunks to print linearly (also supports "unlimited"/0
or negative numbers to print chunks going backwards)"""
            )
        group.add_argument(
            "-x", "--hexdump", dest="hexdump", action="store_true", default=False,
            help="Hexdump the chunk contents"
        )
        group.add_argument(
            "-X", dest="hexdump_unit", type=h.check_hexdump_unit, default=1,
            help=f"Specify hexdump unit ({h.prepare_list(h.hexdump_units)}) when using -x (default: %(default)s)"
        )
        group.add_argument(
            "-m", "--maxbytes", dest="maxbytes", type=h.string_to_int, default=0,
            help="Max bytes to dump with -x"
        )
        if self.name == "ptchunk":
            group.add_argument(
                "-n", dest="no_newline", action="store_true", default=False,
                help="Do not output the trailing newline (summary representation)"
            )
        group.add_argument(
            "-p", dest="print_offset", type=h.string_to_int, default=0,
            help="Print data inside at given offset (summary representation)"
        )
        group.add_argument(
            "-M", "--metadata", dest="metadata", type=str, default=None,
            help="Comma separated list of metadata to print (previously stored with the 'ptmeta' command)"
        )
        if self.name == "ptchunk" or self.name == "ptlist":
            group.add_argument(
                "-I", "--highlight-types", dest="highlight_types", type=str, default=None,
                help="Comma separated list of chunk types (M, F, f or t) for chunks we want to highlight in the output"
            )
        group.add_argument(
            "-H", "--highlight-addresses", dest="highlight_addresses", type=str, default=None,
            help="Comma separated list of addresses for chunks we want to highlight in the output"
        )
        group.add_argument(
            "-G", "--highlight-metadata", dest="highlight_metadata", type=str, default=None,
            help="""Comma separated list of metadata (previously stored with the 'ptmeta' command) 
for chunks we want to highlight in the output"""
        )
        group.add_argument(
            "--highlight-only", dest="highlight_only", action="store_true", default=False,
            help="Only show the highlighted chunks (instead of just '*' them)"
        )
        if self.name != "ptfree":
            group.add_argument(
                "--use-cache", dest="use_cache", action="store_true", default=False,
                help="""Do not fetch any internal ptmalloc data if you know they haven't changed since
last time they were cached"""
            )
        group.add_argument(
            "--json", dest="json_filename", type=str, default=None,
            help="Specify the json filename to save the output (Useful to diff 2 outputs)"
        )
        group.add_argument(
            "--json-append", dest="json_append", action="store_true", default=False,
            help="Append to the filename instead of overwriting"
        )
        group.add_argument(
            "-s", "--search", dest="search_value", type=str, default=None,
            help="Search a value and show match/no match"
        )
        group.add_argument(
            "-S", "--search-type", dest="search_type", type=str, default="string",
            help=f"Specify search type ({h.prepare_list(ptchunk.search_types)}) when using -s (default: %(default)s)"
        )
        group.add_argument(
            "--match-only", dest="match_only", action="store_true", default=False,
            help="Only show the matched chunks (instead of just show match/no match)"
        )
        group.add_argument(
            "--skip-header", dest="skip_header", action="store_true", default=False,
            help="Don't include chunk header contents in search results"
        )
        group.add_argument(
            "--depth", dest="search_depth", type=h.string_to_int, default=0,
            help="How far into each chunk to search, starting from chunk header address"
        )
        group.add_argument(
            "--cmds", dest="commands", type=str, default=None,
            help="""Semi-colon separated list of debugger commands to be executed for each chunk that is displayed 
('@' is replaced by the chunk address)"""
        )
        # allows to enable a different log level during development/debugging
        self.parser.add_argument(
            "--loglevel", dest="loglevel", default=None,
            help=argparse.SUPPRESS
        )
        # Debug and force printing stuff
        self.parser.add_argument(
            "-d", "--debug", dest="debug", action="store_true", default=False,
            help=argparse.SUPPRESS
        )
        group.add_argument(
            "-o", "--address-offset", dest="address_offset", action="store_true", default=False,
            help="Print offsets from the first printed chunk instead of addresses"
        )

    @h.catch_exceptions
    @ptcmd.ptcmd.init_and_cleanup
    def invoke(self, arg, from_tty):
        """Inherited from gdb.Command
        See https://sourceware.org/gdb/current/onlinedocs/gdb/Commands-In-Python.html
        """

        log.debug("ptchunk.invoke()")

        self.cache.update_all(show_status=self.args.debug, use_cache=self.args.use_cache)

        log.debug("ptchunk.invoke() (2)")

        ptchunk.prepare_args_if_negative_count(self)
        chunks = ptchunk.parse_many2(self)

        if self.args.json_filename != None:
            ptchunk.dump_json(self, chunks, append=self.args.json_append)

    @staticmethod 
    def prepare_args_if_negative_count(self):
        """This is a little bit of a hack. The idea is to handle cases
        where the user wants to print N chunks going backwards.
        We are going to list all the chunks in the arena until we find all 
        the addresses requested and then craft new arguments as if the user
        requested to print from new addresses N chunks before the requested
        addresses before calling parse_many2()
        """

        self.args.reverse = False
        # Nothing to do if the count is positive or unlimited
        if self.args.count == None or self.args.count >= 0:
            return
        # We are making the count positive
        self.args.count = self.args.count*-1
        # And we print N chunks before the requested chunk + the actual chunk
        self.args.count += 1
        
        addresses = self.dbg.parse_address(self.args.addresses)
        if len(addresses) == 0:
            pu.print_error("WARNING: No valid address supplied")
            self.parser.print_help()
            return []
        # We will fill it with new addresses later below
        self.args.addresses = []

        # Let's get all the chunks' addresses in the arena

        mstate = self.cache.mstate
        par = self.cache.par

        if mstate.address == self.cache.main_arena_address:
            addr, _ = self.dbg.get_heap_address(par)
        else:
            print("Using manual arena calculation for heap start")
            addr = (mstate.address + mstate.size + self.ptm.MALLOC_ALIGN_MASK) & ~self.ptm.MALLOC_ALIGN_MASK

        chunks_addresses = []
        chunks_addresses.append(addr)
        while True:
            p = mc.malloc_chunk(
                self.ptm, 
                addr, 
                read_data=False, 
                debugger=self.dbg,
                use_cache=True
            )
            if not p.initOK:
                pu.print_error("WARNING: Stopping due to invalid chunk parsed in arena")
                break
            chunks_addresses.append(addr)

            if p.address == self.ptm.top(self.cache.mstate):
                break

            addr = self.ptm.next_chunk(p)

        # Prepare arguments for "ptchunk" format
        # i.e. for every address, get the new address N chunks before
        for addr in addresses:
            try:
                index = chunks_addresses.index(addr)
            except ValueError:
                pu.print_error(f"WARNING: Could not find {addr:#x} in arena, skipping")
                continue
            index -= self.args.count
            if index < 0:
                pu.print_error(f"WARNING: Reaching beginning of arena with {addr:#x}")
                index = 0
            self.args.addresses.append(f"{chunks_addresses[index]:#x}")
        

    @staticmethod
    def parse_many2(self,
        inuse=None,
        tcache=None,
        fast=None,
        allow_invalid=False,
        separate_addresses_non_verbose=True,
        header_once=None,
        count_handle=None,
        count_printed=None,
    ):
        """Most arguments are shared by "ptchunk" and "ptlist" commands.
        This function allows for "ptlist" to call into "ptchunk"

        :param inuse: True if we know it is an inuse chunk (i.e. not in any bin) (not required)
        :param tcache: True if we know all the chunks are in the tcache bins,
                        False if we know they are NOT in the tcache bins. 
                        None otherwise.
                        Useful to specify when parsing a tcache bin
        :param fast: Same as "tcache" but for fast bins
        :param allow_invalid: sometimes these structures will be used for
                              that isn't actually a complete chunk, like a freebin, in these cases we
                              still wanted to be able to parse so that we can access the forward and
                              backward pointers, so shouldn't complain about their being invalid size
        :param separate_addresses_non_verbose: False to avoid a separation when printing
                                               one-line chunks, like in freebins
        :param header_once: string to print before printing the first chunk, or None if not needed
        :param count_handle: maximum number of chunks to handle per address, even if not printed, or None if unlimited
        :param count_printed: maximum number of chunks to print in total for all addresses, or None if unlimited.
                              Only useful if handling a freebin.
        :return: the list of malloc_chunk() found

        Note that it is a static method but it has self as a first
        argument to make it easier to read its implementation
        """
        addresses = []
        if not self.args.addresses:
            print("WARNING: No address supplied?")
            self.parser.print_help()
            return []
        else:
            addresses = self.dbg.parse_address(self.args.addresses)
            if len(addresses) == 0:
                pu.print_error("WARNING: No valid address supplied")
                self.parser.print_help()
                return []

        if self.args.hexdump_unit not in h.hexdump_units:
            pu.print_error("Wrong hexdump unit specified")
            self.parser.print_help()
            return []
        hexdump_unit = self.args.hexdump_unit
        count = self.args.count
        search_depth = self.args.search_depth
        skip_header = self.args.skip_header
        print_offset = self.args.print_offset
        metadata = self.args.metadata
        verbose = self.args.verbose
        no_newline = self.args.no_newline
        debug = self.args.debug
        hexdump = self.args.hexdump
        maxbytes = self.args.maxbytes
        commands = self.args.commands
        address_offset = self.args.address_offset

        if self.args.search_type not in ptchunk.search_types:
            pu.print_error(f"Wrong search type specified {self.args.search_type}")
            self.parser.print_help()
            return []
        if self.args.search_type != "string" and not self.args.search_value.startswith("0x"):
            pu.print_error("Wrong search value for specified type")
            self.parser.print_help()
            return []
        search_value = self.args.search_value
        search_type = self.args.search_type
        match_only = self.args.match_only

        highlight_only = self.args.highlight_only
        highlight_addresses = []
        if self.args.highlight_addresses:
            list_highlight_addresses = [e.strip() for e in self.args.highlight_addresses.split(",")]
            highlight_addresses = self.dbg.parse_address(list_highlight_addresses)
            if len(highlight_addresses) == 0:
                pu.print_error("WARNING: No valid address to highlight supplied")
                self.parser.print_help()
                return []
        highlight_metadata = []
        if self.args.highlight_metadata:
            highlight_metadata = [e.strip() for e in self.args.highlight_metadata.split(",")]

        # some commands inheriting ptchunk arguments don't support highlighting types
        try:
            highlight_types = self.args.highlight_types
        except AttributeError:
            highlight_types = None
        if highlight_types:
            highlight_types = [e.strip() for e in highlight_types.split(",")]
            for e in highlight_types:
                if e not in ["M", "F", "f", "t"]:
                    pu.print_error("WARNING: Invalid type to highlight supplied")
                    self.parser.print_help()
                    return []
        else:
            highlight_types = []


        all_chunks = []
        chunks = None
        for address in addresses:
            if chunks is not None and len(chunks) > 0 and \
            (separate_addresses_non_verbose or verbose > 0):
                print("-" * 60)

            if count_printed == None:
                count_linear = count
            elif count == None:
                count_linear = count_printed
            else:
                count_linear = min(count_printed, count)
            chunks = ptchunk.parse_many(
                address, self.ptm, self.dbg, count_linear, count_handle, search_depth,
                skip_header, hexdump_unit, search_value, 
                search_type, match_only, print_offset, verbose, no_newline,
                debug, hexdump, maxbytes, metadata,
                highlight_types=highlight_types,
                highlight_addresses=highlight_addresses,
                highlight_metadata=highlight_metadata,
                highlight_only=highlight_only,
                inuse=inuse, tcache=tcache, fast=fast, allow_invalid=allow_invalid,
                header_once=header_once, commands=commands,
                use_cache=True, # we enforced updating the cache once above so no need to do it for every chunk
                address_offset=address_offset
            )
            if chunks is not None and len(chunks) > 0:
                all_chunks.extend(chunks)
                if count_printed != None:
                    count_printed -= len(chunks)
                header_once = None
            if count_printed == 0:
                break
        return all_chunks

    # XXX - probably ptm can just have the debugger
    @staticmethod
    def parse_many(address, ptm, dbg=None, count=1, count_handle=None, search_depth=0, 
        skip_header=False, hexdump_unit=1, search_value=None,
        search_type=None, match_only=False, print_offset=0, verbose=0, no_newline=False,
        debug=False, hexdump=False, maxbytes=0, metadata=None,
        highlight_types=[], highlight_addresses=[], highlight_metadata=[], highlight_only=False, 
        inuse=None, tcache=None, fast=None, allow_invalid=False,
        header_once=None, commands=None,
        use_cache=False, address_offset=False
    ):
        """Parse many chunks starting from a given address and show them based
        passed arguments

        :param address: chunk's address to start parsing from
        :param ptm: ptmalloc object (libptmalloc constants and helpers)
        :param dbg: pydbg object (debugger interface)
        :param count: see ptchunk's ArgumentParser definition
                      maximum number of chunks to print, or None if unlimited
        :param count_handle: maximum number of chunks to handle per address, even if not printed, or None if unlimited
        :param search_depth: see ptchunk's ArgumentParser definition
        :param skip_header: see ptchunk's ArgumentParser definition
        :param hexdump_unit: see ptchunk's ArgumentParser definition
        :param search_value: see ptchunk's ArgumentParser definition
        :param search_type: see ptchunk's ArgumentParser definition
        :param match_only: see ptchunk's ArgumentParser definition
        :param print_offset: see ptchunk's ArgumentParser definition
        :param verbose: see ptchunk's ArgumentParser definition
        :param no_newline: see ptchunk's ArgumentParser definition
        :param debug: see ptchunk's ArgumentParser definition
        :param hexdump: see ptchunk's ArgumentParser definition
        :param maxbytes: see ptchunk's ArgumentParser definition
        :param metadata: see ptchunk's ArgumentParser definition
        :param highlight_types: list of types. highlight chunks with matching type with a '*' e.g. to be used by 'ptlist'
        :param highlight_addresses: list of addresses. highlight chunks with matching address with a '*' e.g. to be used by 'ptlist'
        :param highlight_metadata: list of metadata. highlight chunks with matching metadata with a '*' e.g. to be used by 'ptlist'
        :param highlight_only: see ptchunk's ArgumentParser definition
        :param inuse: True if we know all the chunks are inuse (i.e. not in any bin)
                      False if we know they are NOT in inuse.
                      None otherwise.
                      Useful to specify when parsing a regular bin
        :param tcache: True if we know all the chunks are in the tcache bins,
                        False if we know they are NOT in the tcache bins. 
                        None otherwise.
                        Useful to specify when parsing a tcache bin
        :param fast: Same as "tcache" but for fast bins
        :param allow_invalid: sometimes these structures will be used for
                              that isn't actually a complete chunk, like a freebin, in these cases we
                              still wanted to be able to parse so that we can access the forward and
                              backward pointers, so shouldn't complain about their being invalid size
        :param header_once: string to print before printing the first chunk, or None if not needed
        :param commands: see ptchunk's ArgumentParser definition
        :param use_cache: see ptchunk's ArgumentParser definition
        :param address_offset: see ptchunk's ArgumentParser definition

        :return: the list of malloc_chunk being parsed and already shown
        """
        chunks = []

        highlight_types2 = []
        highlight_types = set(highlight_types)
        for t in highlight_types:
            if t == "M":
                highlight_types2.append(pt.chunk_type.INUSE)
            elif t == "F":
                highlight_types2.append(pt.chunk_type.FREE_SMALL)
                highlight_types2.append(pt.chunk_type.FREE_LARGE)
            elif t == "f":
                highlight_types2.append(pt.chunk_type.FREE_FAST)
            elif t == "t":
                highlight_types2.append(pt.chunk_type.FREE_TCACHE)
            else:
                print("ERROR: invalid chunk type provided, should not happen")
                return []
        highlight_addresses = set(highlight_addresses)
        highlight_metadata = set(highlight_metadata)
        highlight_metadata_found = set([])


        p = mc.malloc_chunk(
            ptm, 
            addr=address, 
            debugger=dbg, 
            use_cache=use_cache,
            tcache=tcache,
            fast=fast,
            allow_invalid=allow_invalid
        )
        if not p.initOK:
            return
        first_address = p.address
        dump_offset = 0
        while True:
            prefix = "" # used for one-line output
            suffix = "" # used for one-line output
            epilog = "" # used for verbose output

            colorize_func = str # do not colorize by default
            if metadata is not None:
                opened = False
                list_metadata = [e.strip() for e in metadata.split(",")]
                L, s, e, colorize_func = ptmeta.get_metadata(p.address, list_metadata=list_metadata)
                suffix += s
                epilog += e
                p.metadata = L # save so we can easily export to json later

            if search_value is not None:
                if not dbg.search_chunk(
                    ptm, p, search_value, search_type=search_type,
                    depth=search_depth, skip=skip_header
                ):
                    found_match = False
                    suffix += " [NO MATCH]"
                else:
                    suffix += pu.light_green(" [MATCH]")
                    found_match = True

            # XXX - the current representation is not really generic as we print the first short
            # as an ID and the second 2 bytes as 2 characters. We may want to support passing the
            # format string as an argument but this is already useful
            if print_offset != 0:
                mem = dbg.read_memory(
                    p.data_address + print_offset, 4
                )
                (id_, desc) = struct.unpack_from("<H2s", mem, 0x0)
                if h.is_ascii(desc):
                    suffix += " 0x%04x %s" % (id_, str(desc, encoding="utf-8"))
                else:
                    suffix += " 0x%04x hex(%s)" % (
                        id_,
                        str(binascii.hexlify(desc), encoding="utf-8"),
                    )

            # Only print the chunk type for non verbose
            if p.address == ptm.cache.par.sbrk_base:
                suffix += " (sbrk_base)"
            elif p.address == ptm.top(ptm.cache.mstate):
                suffix += " (top)"

            printed = False
            if verbose == 0:
                found_highlight = False
                # Only highlight chunks for non verbose
                if p.address in highlight_addresses:
                    found_highlight = True
                    highlight_addresses.remove(p.address)
                if p.type in highlight_types2:
                    found_highlight = True
                if len(highlight_metadata) > 0:
                    # We retrieve all metadata since we want to highlight chunks containing any of the
                    # metadata, even if we don't show some of the metadata
                    _, s, _, _ = ptmeta.get_metadata(p.address, list_metadata="all")
                    for m in highlight_metadata:
                        # we check in the one-line output as it should have less non-useful information
                        if m in s:
                            found_highlight = True
                            highlight_metadata_found.add(m)
                if found_highlight:
                    prefix += "* "
                if (not highlight_only or found_highlight) \
                    and (not match_only or found_match):
                    if header_once != None:
                        print(header_once)
                        header_once = None
                    if no_newline:
                        print(prefix + ptm.chunk_info(p, colorize_func=colorize_func, first_address=first_address, address_offset=address_offset) + suffix, end="")
                    else:
                        print(prefix + ptm.chunk_info(p, colorize_func=colorize_func, first_address=first_address, address_offset=address_offset) + suffix)
                    printed = True
            elif verbose >= 1 and (not match_only or found_match):
                if header_once != None:
                    print(header_once)
                    header_once = None
                print(p)
                printed = True
                # XXX - this is old code used in Cisco ASA. Need removal or merge?
                if ptm.ptchunk_callback is not None:
                    size = ptm.chunksize(p) - p.hdr_size
                    if p.data_address is not None:
                        # We can provide an excess of information and the
                        # callback can choose what to use
                        cbinfo = {}
                        cbinfo["caller"] = "ptchunk"
                        cbinfo["allocator"] = "ptmalloc"
                        cbinfo["addr"] = p.data_address
                        cbinfo["hdr_sz"] = p.hdr_size
                        cbinfo["chunksz"] = ptm.chunksize(p)
                        cbinfo["min_hdr_sz"] = ptm.INUSE_HDR_SZ
                        cbinfo["data_size"] = size
                        cbinfo["inuse"] = p.inuse
                        cbinfo["size_sz"] = ptm.SIZE_SZ
                        if debug:
                            cbinfo["debug"] = True
                            print(cbinfo)
                        # We expect callback to tell us how much data it
                        # 'consumed' in printing out info
                        dump_offset = ptm.ptchunk_callback(cbinfo)
                    # mem-based callbacks not yet supported
            if printed:
                if hexdump:
                    dbg.print_hexdump_chunk(ptm, p, maxlen=maxbytes, off=dump_offset, unit=hexdump_unit, verbose=verbose)
                if verbose >= 1 and epilog:
                    print(epilog, end="")
                if commands:
                    for command in commands.split(";"):
                        formatted_command = command.replace("@", f"{p.address:#x}")
                        print(dbg.execute(formatted_command))
                chunks.append(p)
                if count != None:
                    count -= 1
            if count_handle != None:
                count_handle -= 1
            if count != 0 and count_handle != 0:
                if printed and (verbose >= 1 or hexdump):
                    print("--")
                if p.is_top:
                    # Only print the chunk type for non verbose
                    if verbose == 0:
                        if ptm.cache.mstate.address == ptm.cache.main_arena_address:
                            start = ptm.cache.par.sbrk_base
                        else:
                            # XXX - seems mstate is at offset 0x20 so there is 0x10 unknown bytes and 0x10 bytes for the chunk
                            # header holding the mstate. So aligning to page works?
                            start = ((ptm.cache.mstate.address & ~0xfff) + ptm.MALLOC_ALIGN_MASK) & ~ptm.MALLOC_ALIGN_MASK
                        end = int(start + ptm.cache.mstate.max_system_mem)
                        if address_offset is True:
                            end -= first_address
                        if ptm.cache.mstate.address == ptm.cache.main_arena_address:
                            print("{:#x}".format(end), end="")
                            print(" (sbrk_end)")
                        else:
                            print("{:#x}".format(end))
                    else:
                        print("Stopping due to end of heap")
                    break
                p = mc.malloc_chunk(
                    ptm,
                    addr=(p.address + ptm.chunksize(p)),
                    debugger=dbg,
                    use_cache=use_cache,
                    tcache=tcache,
                    fast=fast,
                    allow_invalid=allow_invalid
                )
                if not p.initOK:
                    break
            else:
                break

        if len(highlight_addresses) != 0:
            pu.print_error("WARNING: Could not find these chunk addresses: %s" % (", ".join(["0x%x" % x for x in highlight_addresses])))
        if len(highlight_metadata-highlight_metadata_found) != 0:
            pu.print_error("WARNING: Could not find these metadata: %s" % (", ".join(list(highlight_metadata-highlight_metadata_found))))

        return chunks

    @staticmethod
    def dump_json(self, chunks, append=False):
        """Dump the chunks into a json format

        :param self: ptchunk or ptlist object for convenience
        :param chunks: list of malloc_chunk objects returned by parse_many()
        :param append: True if wants to append to an existing file instead of overwriting

        Note that it is a static method but it has self as a first
        argument to make it easier to read its implementation
        """

        json_filename = self.args.json_filename
        metadata = self.args.metadata
        prepared_chunks = []
        if append and os.path.exists(json_filename):
            prepared_chunks = json.loads(open(json_filename, "r").read())

        first_address = chunks[0].address
        for p in chunks:
            offset = p.address - first_address
            entry = {}
            entry["off"] = f"{offset:#x}"
            data_address = p.address + p.hdr_size
            data_size = self.ptm.chunksize(p) - p.hdr_size
            mem = self.dbg.read_memory(data_address, data_size)
            if p.type == pt.chunk_type.FREE_FAST:
                entry["type"] = "f"
            elif p.type == pt.chunk_type.FREE_TCACHE:
                entry["type"] = "t"
            elif p.type == pt.chunk_type.INUSE:
                entry["type"] = "M"
            else:
                entry["type"] = "F"
            entry["sz"] = f"{self.ptm.chunksize(p):#x}"
            if self.args.hexdump:
                entry["data"] = binascii.hexlify(mem).decode("utf-8")
            if metadata:
                entry["metadata"] = p.metadata
            prepared_chunks.append(entry)

        print("Writing to %s" % json_filename)
        open(json_filename, "w").write(json.dumps(prepared_chunks, indent=4))
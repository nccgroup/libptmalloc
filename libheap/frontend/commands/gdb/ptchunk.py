from __future__ import print_function

import argparse
import binascii
import struct
import sys

import libheap.frontend.helpers as h
from libheap.frontend.printutils import print_error, print_header
from libheap.ptmalloc.malloc_chunk import malloc_chunk
from libheap.ptmalloc.ptmalloc import ptmalloc

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")


class ptchunk(gdb.Command):
    """libheap command help listing"""

    def __init__(self, ptm, debugger=None, version=None):
        super(ptchunk, self).__init__("ptchunk", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

        self.ptm = ptm
        if debugger is not None:
            self.debugger = debugger
        else:
            print_error("Please specify a debugger")
            raise Exception("sys.exit()")

        self.version = version

    def help(self):
        """print the command usage """

        print(
            "usage: ptchunk [-v] [-f] [-x] [-n] [-p <offset>] [-c <count>] [-s <val>] [--depth <depth>] <addr>"
        )
        print(" -v      use verbose output (multiples for more verbosity)")
        print(" -f      use <addr> explicitly, rather than be smart")
        print(" -x      hexdump the chunk contents")
        print(" -m      max bytes to dump with -x")
        print(" -c      number of chunks to print")
        print(" -s      search 32-bit value pattern when print chunks")
        print(" --search-byte  search 8-bit value pattern when print chunks")
        print(" --search-word  search 16-bit value pattern when print chunks")
        print(" --search-dword search 31-bit value pattern when print chunks")
        print(" --search-qword search 64-bit value pattern when print chunks")
        print(" --search-string search for NULL string pattern when print chunks")
        print(" --depth how far into each chunk to search, starting from chunk header address")
        print(" --skip-header don't include header contents in search results")
        print(" -d      debug and force printing stuff")
        print(" -n      do not output the trailing newline (summary representation)")
        print(" -p      print data inside at given offset (summary representation)")
        print(" <addr>  a ptmalloc chunk header")
        print("Flag legend: P=PREV_INUSE, M=MMAPPED, N=NON_MAIN_ARENA")

    def invoke(self, arg, from_tty):
        try:
            self.invoke_(arg, from_tty)
        except Exception:
            h.show_last_exception()

    # XXX - this should move to a debug helper
    def parse_address(self, addresses):
        """Parse one or more addresses or gdb variables.

        :address: an address string containing hex, int, or variable
        :returns: the resolved addresses as integers

        It this should be able to handle: hex, decimal, program variables
        without &, program variables with &, gdb variables starting with $,
        basic addition and subtraction of variables, etc
        """
        resolved = []
        if type(addresses) != list:
            addresses = [addresses]
        for item in addresses:
            addr = None
            try:
                addr = self.debugger.parse_variable(item)
            except:
                try:
                    addr = self.debugger.parse_variable("&" + item)
                except:
                    print(f"ERROR: Unable to parse {item}")
                    continue
            if addr is not None:
                resolved.append(addr)
        return resolved

    def invoke_(self, arg, from_tty):

        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument(
            "-v", "--verbose", dest="verbose", action="count", default=0,
        )
        parser.add_argument(
            "-h", "--help", dest="help", action="store_true", default=False,
        )
        parser.add_argument(
            "-f", dest="force", action="store_true", default=False,
        )
        parser.add_argument(
            "-x", "--hexdump", dest="hexdump", action="store_true", default=False,
        )
        parser.add_argument(
            "-d", "--debug", dest="debug", action="store_true", default=False,
        )
        parser.add_argument(
            "-c", "--count", dest="count", type=h.string_to_int, default=1,
        )
        parser.add_argument(
            "-m", "--maxbytes", dest="maxbytes", type=h.string_to_int, default=0,
        )
        parser.add_argument(
            "-n", dest="no_newline", action="store_true", default=False,
        )
        parser.add_argument(
            "-p", dest="print_offset", type=h.string_to_int, default=0,
        )
        parser.add_argument(
            "-s", "--search-dword", dest="search_value_32", type=str, default=None,
        )
        parser.add_argument(
            "--search-byte", dest="search_value_8", type=str, default=None,
        )
        parser.add_argument(
            "--search-word", dest="search_value_16", type=str, default=None,
        )
        parser.add_argument(
            "--search-qword", dest="search_value_64", type=str, default=None,
        )
        parser.add_argument(
            "--search-string", dest="search_value_string", type=str, default=None,
        )
        parser.add_argument(
            "--skip-header", dest="skip_header", action="store_true", default=False,
        )

        parser.add_argument(
            "--depth", dest="search_depth", type=h.string_to_int, default=0,
        )
        parser.add_argument(
            "addresses", nargs="*", default=None,
        )

        args = parser.parse_args(arg.split())
        if args.help:
            self.help()
            return

        addresses = []
        if not args.addresses:
            print("WARNING: No address supplied?")
            self.help()
            return
        else:
            addresses = self.parse_address(args.addresses)
            if len(addresses) == 0:
                print_error("WARNING: No valid address supplied")
                self.help()
                return

        search_value = None
        if args.search_value_8:
            search_value = args.search_value_8
            search_width = "8"
        elif args.search_value_16:
            search_value = args.search_value_16
            search_width = "16"
        elif args.search_value_32:
            search_value = args.search_value_32
            search_width = "32"
        elif args.search_value_64:
            search_value = args.search_value_64
            search_width = "64"
        elif args.search_value_string:
            search_value = args.search_value_string
            search_width = "string"

        ptm = ptmalloc(debugger=self.debugger)
        ptm.set_globals()

        bFirst = True
        for address in addresses:
            if bFirst:
                bFirst = False
            else:
                print("-" * 60)

            # XXX - probably ptm can just have the debugger
            p = malloc_chunk(ptm, addr=address, debugger=self.debugger)
            if not p.initOK:
                return
            count = args.count
            dump_offset = 0
            while True:
                suffix = ""
                if search_value is not None:
                    # Don't print if the chunk doesn't have the pattern
                    if not self.ptm.search_chunk(
                        p, search_value, width=search_width,
                        depth=args.search_depth, skip=args.skip_header
                    ):
                        suffix += " [NO MATCH]"
                    else:
                        suffix += " [MATCH]"
                # XXX - the current representation is not really generic as we print the first short
                # as an ID and the second 2 bytes as 2 characters. We may want to support passing the
                # format string as an argument but this is already useful
                if args.print_offset != 0:
                    mem = self.debugger.read_memory(
                        p.data_address + args.print_offset, 4
                    )
                    (id_, desc) = struct.unpack_from("<H2s", mem, 0x0)
                    if h.is_ascii(desc):
                        suffix += " 0x%04x %s" % (id_, str(desc, encoding="utf-8"))
                    else:
                        suffix += " 0x%04x hex(%s)" % (
                            id_,
                            str(binascii.hexlify(desc), encoding="utf-8"),
                        )

                if args.verbose == 0:
                    if args.no_newline:
                        print(self.ptm.chunk_info(p) + suffix, end="")
                    else:
                        print(self.ptm.chunk_info(p) + suffix)
                elif args.verbose == 1:
                    print(p)
                    if self.ptm.ptchunk_callback is not None:
                        size = self.ptm.chunksize(p) - p.hdr_size
                        if p.data_address is not None:
                            # We can provide an excess of information and the
                            # callback can choose what to use
                            cbinfo = {}
                            cbinfo["caller"] = "ptchunk"
                            cbinfo["allocator"] = "ptmalloc"
                            cbinfo["addr"] = p.data_address
                            cbinfo["hdr_sz"] = p.hdr_size
                            cbinfo["chunksz"] = self.ptm.chunksize(p)
                            cbinfo["min_hdr_sz"] = self.ptm.INUSE_HDR_SZ
                            cbinfo["data_size"] = size
                            cbinfo["inuse"] = p.inuse
                            cbinfo["size_sz"] = self.ptm.SIZE_SZ
                            if args.debug:
                                cbinfo["debug"] = True
                                print(cbinfo)
                            # We expect callback to tell us how much data it
                            # 'consumed' in printing out info
                            dump_offset = self.ptm.ptchunk_callback(cbinfo)
                        # mem-based callbacks not yet supported
                if args.hexdump:
                    # XXX - this should switch to use gef hexdump or something
                    self.ptm.print_hexdump(p, args.maxbytes, dump_offset)
                count -= 1
                if count != 0:
                    if args.verbose == 1 or args.hexdump:
                        print("--")
                    p = malloc_chunk(
                        self.ptm,
                        addr=(p.address + self.ptm.chunksize(p)),
                        debugger=self.debugger,
                    )
                    if not p.initOK:
                        break
                else:
                    break

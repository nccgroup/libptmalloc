# -*- coding: future_fstrings -*-
from __future__ import print_function

import argparse
import binascii
import struct
import sys
import logging

from libptmalloc.frontend import printutils as pu
from libptmalloc.ptmalloc import ptmalloc as pt
from libptmalloc.frontend import helpers as h
from libptmalloc.frontend.commands.gdb import ptcmd

log = logging.getLogger("libptmalloc")
log.trace("ptparam.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")  

class ptparam(ptcmd.ptcmd):
    """Command to print information about malloc parameters represented by the malloc_par structure
    """

    def __init__(self, ptm):
        log.debug("ptparam.__init__()")
        super(ptparam, self).__init__(ptm, "ptparam")

        self.parser = argparse.ArgumentParser(
            description="""Print malloc parameter(s) information

Analyze the malloc_par structure's fields.""", 
            add_help=False, 
            formatter_class=argparse.RawTextHelpFormatter,
            epilog='NOTE: Last defined mp_ will be cached for future use')
        # self.parser.add_argument(
        #     "-v", "--verbose", dest="verbose", action="count", default=0,
        #     help="Use verbose output (multiple for more verbosity)"
        # )
        self.parser.add_argument(
            "-h", "--help", dest="help", action="store_true", default=False,
            help="Show this help"
        )
        self.parser.add_argument(
            "-l", dest="list", action="store_true", default=False,
            help="List malloc parameter(s)' address only"
        )
        self.parser.add_argument(
            "--use-cache", dest="use_cache", action="store_true", default=False,
            help="Do not fetch parameters data if you know they haven't changed since last time they were cached"
        )
        self.parser.add_argument(
            "address", default=None, nargs="?", type=h.string_to_int,
            help="A malloc_par struct address. Optional with cached malloc parameters"
        )
        # allows to enable a different log level during development/debugging
        self.parser.add_argument(
            "--loglevel", dest="loglevel", default=None,
            help=argparse.SUPPRESS
        )

    @h.catch_exceptions
    @ptcmd.ptcmd.init_and_cleanup
    def invoke(self, arg, from_tty):
        """Inherited from gdb.Command
        See https://sourceware.org/gdb/current/onlinedocs/gdb/Commands-In-Python.html
        """

        log.debug("ptparam.invoke()")

        self.cache.update_param(self.args.address, show_status=True, use_cache=self.args.use_cache)

        if self.args.list:
            self.list_parameters()
            return

        print(self.cache.par)

    def list_parameters(self):
        """List malloc parameter(s)' address only"""

        par = self.cache.par

        print("Parameter(s) found:", end="\n")
        print("  parameter @ ", end="")
        pu.print_header("{:#x}".format(int(par.address)), end="\n")
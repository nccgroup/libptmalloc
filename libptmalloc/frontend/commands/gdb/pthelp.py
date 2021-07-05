# -*- coding: future_fstrings -*-
from __future__ import print_function

import sys
import logging

from libptmalloc.frontend import printutils as pu
from libptmalloc.ptmalloc import malloc_state as ms
from libptmalloc.ptmalloc import ptmalloc as pt
from libptmalloc.frontend import helpers as h
from libptmalloc.frontend.commands.gdb import ptcmd

log = logging.getLogger("libptmalloc")
log.trace("pthelp.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")

class pthelp(ptcmd.ptcmd):
    """Command to list all available commands"""

    def __init__(self, ptm, commands=[]):
        log.debug("pthelp.__init__()")
        super(pthelp, self).__init__(ptm, "pthelp")

        self.cmds = commands

    @h.catch_exceptions
    def invoke(self, arg, from_tty):
        """Inherited from gdb.Command
        See https://sourceware.org/gdb/current/onlinedocs/gdb/Commands-In-Python.html

        Print the usage of all the commands
        """

        pu.print_header("{:<20}".format("pthelp"), end="")
        print("List all libptmalloc commands")
        for cmd in self.cmds:
            if cmd.parser != None:
                # Only keep the first line of the description which should be short
                description = cmd.parser.description.split("\n")[0]
            elif cmd.description != None:
                description = cmd.description
            else:
                description = "Unknown"
            pu.print_header("{:<20}".format(cmd.name), end="")
            print(description)
        print("Note: Use a command name with -h to get additional help")
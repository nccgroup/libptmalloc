from __future__ import print_function

import argparse
import binascii
import struct
import sys
import logging
import importlib
import pprint
import re

import libptmalloc.frontend.printutils as pu
importlib.reload(pu)
import libptmalloc.frontend.helpers as h
importlib.reload(h)
import libptmalloc.frontend.commands.gdb.ptcmd as ptcmd # no reload on purpose

log = logging.getLogger("libptmalloc")
log.trace("ptconfig.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")  

class ptconfig(ptcmd.ptcmd):
    """Command to manage ptmalloc configuration"""

    def __init__(self, ptm):
        log.debug("ptconfig.__init__()")
        super(ptconfig, self).__init__(ptm, "ptconfig")

        self.parser = argparse.ArgumentParser(
            description="""Show/change ptmalloc configuration""", 
            formatter_class=argparse.RawTextHelpFormatter,
            add_help=False,
            epilog="""E.g.
  ptconfig
  ptconfig -v 2.27
  ptconfig -t off""")
        self.parser.add_argument(
            "-h", "--help", dest="help", action="store_true", default=False,
            help="Show this help"
        )
        self.parser.add_argument(
            "-v", "--version", dest="version", type=float, default=None,
            help="Change the glibc version manually (e.g. 2.27)"
        )
        self.parser.add_argument(
            "-t", "--tcache", dest="tcache", type=str, default=None,
            help="Enable or disable tcache (on/off)"
        )
        self.parser.add_argument(
            "-o", "--distribution", dest="distribution", type=str, default=None,
            help="Target OS distribution (e.g. debian, ubuntu, centos, photon)"
        )
        self.parser.add_argument(
            "-r", "--release", dest="release", type=str, default=None,
            help="Target OS release version (e.g. 10 for debian, 18.04 for ubuntu, 8 for centos, 3.0 for photon)"
        )
        # allows to enable a different log level during development/debugging
        self.parser.add_argument(
            "--loglevel", dest="loglevel", default=None,
            help=argparse.SUPPRESS
        )

    @staticmethod
    def set_distribution(ptm, distribution):
        if distribution != "photon":
            print("Distribution has default glibc settings, ignoring")
            return
        ptm.distribution = distribution

    @staticmethod
    def set_release(ptm, release):
        if ptm.distribution == "photon":
            if release != "3.0":
                print("Release has default glibc settings for Photon OS, ignoring")
                return
        else:
            print("Unsupported distribution or has default glibc setttings, ignoring")
            return
        ptm.release = release

    @h.catch_exceptions
    @ptcmd.ptcmd.init_and_cleanup
    def invoke(self, arg, from_tty):
        """Inherited from gdb.Command
        See https://sourceware.org/gdb/current/onlinedocs/gdb/Commands-In-Python.html
        """

        log.debug("ptconfig.invoke()")

        updated = False

        if self.args.version != None:
            self.ptm.version = self.args.version
            # Resetting it
            if self.ptm.version >= 2.26:
                self.ptm.tcache_enabled = True
            else:
                self.ptm.tcache_enabled = False
            updated = True

        if self.args.tcache != None:
            if self.args.tcache == "on":
                self.ptm.tcache_enabled = True
            elif self.args.tcache == "off":
                self.ptm.tcache_enabled = False
            else:
                print("Unsupported tcache value, only \"on\" and \"off\" are supported, ignoring")
            updated = True

        if self.args.distribution != None:
            ptconfig.set_distribution(self.ptm, self.args.distribution)
            updated = True

        if self.args.release != None:
            ptconfig.set_release(self.ptm, self.args.release)
            updated = True

        if updated:
            # Resetting some cached info
            self.ptm.cache.mstate = None
            return

        # no argument specified
        d = {}
        d["glibc version"] = self.ptm.version
        if self.ptm.tcache_enabled is True:
            d["tcache"] = "enabled"
        elif self.ptm.tcache_enabled is False:
            d["tcache"] = "disabled"
        if self.ptm.distribution is not None:
            d["distribution"] = self.ptm.distribution
        if self.ptm.release is not None:
            d["release"] = self.ptm.release

        for k,v in d.items():
            pu.print_header("{:<20}".format(k), end="")
            print(v)



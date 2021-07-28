import os
import sys
import importlib

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    sys.exit()

try:
    import configparser  # py3
except:
    import ConfigParser as configparser  # py2

import libptmalloc.frontend.frontend_gdb as fg
importlib.reload(fg)
import libptmalloc.ptmalloc.ptmalloc as pt
importlib.reload(pt)
import libptmalloc.pydbg.debugger as d
importlib.reload(d)
import libptmalloc.pydbg.pygdbpython as pgp
importlib.reload(pgp)
import libptmalloc.frontend.commands.gdb.ptconfig as ptconfig
importlib.reload(ptconfig)
import libptmalloc.frontend.printutils as pu
importlib.reload(pu)

class pyptmalloc:
    """Entry point of libptmalloc"""

    def __init__(self):

        # Setup GDB debugger interface
        debugger = pgp.pygdbpython()
        self.dbg = d.pydbg(debugger)

        config = configparser.SafeConfigParser()
        path = os.path.abspath(os.path.dirname(__file__))
        config.read(os.path.join(path, "libptmalloc.cfg"))

        # atm we only support loading libptmalloc from gdb so it eases the user
        # to know to load it after the program runs
        if not pgp.check_if_gdb_is_running():
            pu.print_error("Please run your program before loading libptmalloc")
            return

        # Try to automatically figure out glibc version and configuration
        glibc_version = self.dbg.get_libc_version()
        if glibc_version is not None:
            self.ptm = pt.ptmalloc(debugger=self.dbg, version=glibc_version)
            if glibc_version >= 2.26:
                # We assume tcache is enabled, and build a malloc_par() 
                # object to check if it seems valid
                self.ptm.cache.update_param(invalid_ok=True)
                par = self.ptm.cache.par
                # XXX - we could check other tcache_* fields of malloc_par() if needed
                if par.tcache_bins != self.ptm.TCACHE_MAX_BINS:
                    self.ptm.tcache_enabled = False
                else:
                    self.ptm.tcache_enabled = True
            else:
                self.ptm.tcache_enabled = False
            print("Detected glibc configuration automatically")

        else:
            # Roll back to user config file
            glibc_version = config.getfloat("Glibc", "version")
            try:
                tcache_enabled = config.getboolean("Glibc", "tcache")
            except configparser.NoOptionError:
                if glibc_version >= 2.26:
                    tcache_enabled = True
                else:
                    tcache_enabled = False

            if tcache_enabled is True and glibc_version < 2.26:
                print("ERROR: configuration file sets tcache enabled but glibc < 2.26 didn't support tcache!")
                raise Exception("sys.exit()")  
            print("Read glibc configuration from config file")

            self.ptm = pt.ptmalloc(debugger=self.dbg, version=glibc_version, tcache_enabled=tcache_enabled)

        try:
            ptconfig.ptconfig.set_distribution(self.ptm, config.get("OperatingSystem", "distribution"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass
        try:
            ptconfig.ptconfig.set_release(self.ptm, config.get("OperatingSystem", "release"))
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass

        # Register GDB commands
        fg.frontend_gdb(self.ptm)

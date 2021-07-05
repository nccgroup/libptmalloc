# -*- coding: future_fstrings -*-
import logging
import shlex
from functools import wraps

from libptmalloc.frontend import printutils as pu

log = logging.getLogger("libptmalloc")
log.trace("ptcmd.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")

class ptcmd(gdb.Command):
    """This is a super class with convenience methods shared by all the commands to:
    - parse the command's arguments/options
    - set/reset a logging level (debugging only)
    """

    def __init__(self, ptm, name):
        self.ptm = ptm
        
        if self.ptm.dbg is None:
            pu.print_error("Please specify a debugger")
            raise Exception("sys.exit()")

        self.name = name
        self.old_level = None
        self.parser = None      # ArgumentParser
        self.description = None # Only use if not in the parser

        super(ptcmd, self).__init__(name, gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    @property
    def version(self):
        """Easily access the version string without going through the ptmalloc object"""
        return self.ptm.version

    @property
    def dbg(self):
        """Easily access the pydbg object without going through the ptmalloc object"""
        return self.ptm.dbg

    @property
    def cache(self):
        """Easily access the cache object without going through the ptmalloc object"""
        return self.ptm.cache

    def set_loglevel(self, loglevel):
        """Change the logging level. This is changed temporarily for the duration
        of the command since reset_loglevel() is called at the end after the command is executed
        """
        if loglevel != None:
            numeric_level = getattr(logging, loglevel.upper(), None)
            if not isinstance(numeric_level, int):
                print("WARNING: Invalid log level: %s" % loglevel)
                return
            self.old_level = log.getEffectiveLevel()
            #print("old loglevel: %d" % self.old_level)
            #print("new loglevel: %d" % numeric_level)
            log.setLevel(numeric_level)

    def reset_loglevel(self):
        """Reset the logging level to the previous one"""
        if self.old_level != None:
            #print("restore loglevel: %d" % self.old_level)
            log.setLevel(self.old_level)
            self.old_level = None

    def init_and_cleanup(f):
        """Decorator for a command's invoke() method

        This allows:
        - not having to duplicate the argument parsing in all commands
        - not having to reset the log level before each of the "return"
          in the invoke() of each command
        """

        @wraps(f)
        def _init_and_cleanup(self, arg, from_tty):
            try:
                self.args = self.parser.parse_args(shlex.split(arg))
            except SystemExit as e:
                # If we specified an unsupported argument/option, argparse will try to call sys.exit()
                # which will trigger such an exception, so we can safely catch it to avoid error messages
                # in gdb
                #h.show_last_exception()
                #raise e
                return
            if self.args.help:
                self.parser.print_help()
                return
            self.set_loglevel(self.args.loglevel)
            f(self, arg, from_tty) # Call actual invoke()
            self.reset_loglevel()
        return _init_and_cleanup
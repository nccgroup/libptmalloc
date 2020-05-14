import os
import sys

# allow someone to manually import the module if they didn't actually install
# it using pip
try_reimport = False
try:
    import libheap
except ImportError:
    module_path = os.path.dirname(os.path.abspath(__file__)) + "/../"
    if module_path not in sys.path:
        sys.path.insert(0, module_path)
    print(sys.path)
    try_reimport = False

if try_reimport:
    try:
        import libheap
    except ImportError:
        print("Couldn't find libheap. Nothing to do")

try:
    from libheap.frontend import frontend_gdb, frontend_gdb_pretty_printers
    from libheap.pydbg.debugger import pydbg
    from libheap.pydbg.pygdbpython import pygdbpython
except ImportError:
    pass

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")

try:
    import configparser  # py3
except:
    import ConfigParser as configparser  # py2


class pyptmalloc:
    def __init__(self):
        # Setup debugger interface
        debugger = pygdbpython()
        self.debugger = pydbg(debugger)

        # Read User Config File
        config = configparser.SafeConfigParser()
        path = os.path.abspath(os.path.dirname(__file__))
        config.read(os.path.join(path, "libheap.cfg"))
        self.glibc_version = float(config.get("Glibc", "version"))

        # Register GDB Commands
        frontend_gdb.frontend_gdb(self.debugger, self.glibc_version)
 
        # Register GDB Pretty Printers
        pp = frontend_gdb_pretty_printers.pretty_print_heap_lookup
        gdb.pretty_printers.append(pp)

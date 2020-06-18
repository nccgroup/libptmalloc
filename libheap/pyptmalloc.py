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
        try_reimport = True
    else:
        print("ERROR: Couldn't find libheap. Nothing to do")

if try_reimport:
    try:
        import libheap
    except ImportError:
        print("ERROR: Couldn't find libheap. Nothing to do")

try:
    from libheap.frontend import frontend_gdb, frontend_gdb_pretty_printers
    from libheap.pydbg.debugger import pydbg
    from libheap.pydbg.pygdbpython import pygdbpython
except ImportError as e:
    print("ERROR: Couldn't find libheap submodules. Nothing to do")
    print(e)
    pass

try:
    import gdb

    is_gdb = True
except ImportError:
    print("Not running inside of GDB, limited functionality...")
    is_gdb = False

try:
    import configparser  # py3
except Exception:
    import ConfigParser as configparser  # py2


class pyptmalloc:
    def __init__(self):
        self.is_gdb = is_gdb

        # Setup debugger interface
        debugger = pygdbpython()
        self.debugger = pydbg(debugger)

        # Read User Config File
        config = configparser.ConfigParser()
        try:
            path = os.path.abspath(os.path.dirname(__file__))
            config.read(os.path.join(path, "libheap.cfg"))
            self.glibc_version = float(config.get("Glibc", "version"))
        except:
            # called directly from inside gdb?
            self.glibc_version = 2.31

        # Register GDB Commands
        frontend_gdb.frontend_gdb(self.debugger, self.glibc_version)

        # Register GDB Pretty Printers
        pp = frontend_gdb_pretty_printers.pretty_print_heap_lookup
        gdb.pretty_printers.append(pp)

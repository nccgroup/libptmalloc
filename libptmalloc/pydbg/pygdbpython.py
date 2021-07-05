import sys
import logging
import importlib
import hexdump
import re
from pathlib import Path
from functools import wraps

import libptmalloc.frontend.printutils as pu
importlib.reload(pu)
import libptmalloc.ptmalloc.malloc_par as mp
importlib.reload(mp)

log = logging.getLogger("libptmalloc")
log.trace("pygdbpython.py")

try:
    import gdb
except ImportError:
    print("Not running inside of GDB, exiting...")
    raise Exception("sys.exit()")

# XXX - could have that into a helper.py instead?
def gdb_is_running(f):
    """Decorator to make sure gdb is running
    """

    @wraps(f)
    def _gdb_is_running(*args, **kwargs):
        if gdb.selected_thread() is not None:
            return f(*args, **kwargs)
        else:
            pu.print_error("GDB is not running.")

    return _gdb_is_running

class pygdbpython:
    """Debugger bridge calling into gdb-specific APIs
    
    See debugger.py interface
    """

    def __init__(self):
        log.debug("pygdbpython.__init__()")

        self.inferior = None
        self.SIZE_SZ = 0

    #
    # Methods from the debugger abstraction
    #

    @gdb_is_running
    def execute(self, cmd, to_string=True):
        """See debugger.py interface
        """

        log.debug("pygdbpython.execute()")
        return gdb.execute(cmd, to_string=to_string)

    def format_address(self, value):
        """See debugger.py interface
        
        Helper for printing gdb.Value on both python 2 and 3
        """
        log.debug("pygdbpython.format_address()")

        try:
            ret = int(value)
        except gdb.error:
            # python2 error: Cannot convert value to int.
            # value.cast(gdb.lookup_type("unsigned long"))
            ret = int(str(value).split(" ")[0], 16)

        return ret

    @gdb_is_running
    def is_remote(self):
        """Return True if remote process debugging, False if local debugging"""
        # (gdb) info target
        # contains "Native process:" if local
        # contains "Extended remote serial target in gdb-specific protocol:" if remote
        # There may be other cases
        pass

    @gdb_is_running
    def get_heap_address(self, par=None):
        """See debugger.py interface
        
        Read heap address from glibc's mp_ structure if available,
        otherwise fall back to /proc/self/maps or
        "info proc mappings" command which are unreliable.
        """
        log.debug("pygdbpython.get_heap_address()")

        start, end = None, None

        if par is not None:
            if isinstance(par, mp.malloc_par):
                start = par.sbrk_base
            else:
                pu.print_error("Please specify a valid malloc_par variable")

            # XXX: add end from arena(s).system_mem ?
        else:
            # ```
            # # cat /proc/self/maps
            # 55555575d000-55555577e000 rw-p 00000000 00:00 0                          [heap]
            # ```
            # XXX - Reading a local file won't work if remote debugging
            #pid, task_id, thread_id = gdb.selected_thread().ptid
            #maps_file = "/proc/%d/task/%d/maps"
            #maps_data = open(maps_file % (pid, task_id)).readlines()
            # for line in maps_data:
            #     if any(x.strip() == "[heap]" for x in line.split(" ")):
            #         heap_range = line.split(" ")[0]
            #         start, end = [int(h, 16) for h in heap_range.split("-")]
            #         break
            # ```
            # (gdb) info proc mappings
            #      0x555555864000     0x55555586e000     0xa000        0x0 [heap]
            # ```
            maps_data = self.execute("info proc mappings").split("\n")
            for line in maps_data:
                if any(x.strip() == "[heap]" for x in line.split(" ")):
                    m = re.match("[\s]*([0-9a-fx]*)[\s]*([0-9a-fx]*).*", line)
                    if m:
                        start = int(m.group(1), 16)
                        end = int(m.group(2), 16)
                        log.debug(f"pygdbpython.get_heap_address() -> {start:#x}, {end:#x}")
                    break

        return start, end

    @gdb_is_running
    def get_size_sz(self):
        """See debugger.py interface
        """

        #log.debug("pygdbpython.get_size_sz()")
        if self.SIZE_SZ != 0:
            return self.SIZE_SZ

        try:
            _machine = self.get_arch()[0]
        except IndexError:
            _machine = ""
            self.SIZE_SZ = 0
            pu.print_error("Retrieving self.SIZE_SZ failed.")
        except TypeError:  # gdb is not running
            _machine = ""
            self.SIZE_SZ = 0
            pu.print_error("Retrieving self.SIZE_SZ failed.")

        if "elf64" in _machine:
            self.SIZE_SZ = 8
        elif "elf32" in _machine:
            self.SIZE_SZ = 4
        else:
            self.SIZE_SZ = 0
            pu.print_error("Retrieving self.SIZE_SZ failed.")

        return self.SIZE_SZ

    @gdb_is_running
    def read_memory(self, address, length):
        """See debugger.py interface
        """
        
        if log.level <= logging.DEBUG:
            if type(address) == int:
                printed_address = "0x%x" % address
            else:
                printed_address = str(address)
            if type(length) == int:
                printed_length = "0x%x" % length
            else:
                printed_length = str(length)
            log.debug(f"pygdbpython.read_memory({printed_address}, {printed_length})")
        if self.inferior is None:
            self.inferior = self.get_inferior()

        return self.inferior.read_memory(address, length)

    @gdb_is_running
    def parse_variable(self, variable=None):
        """See debugger.py interface
        """
        log.debug("pygdbpython.parse_variable()")

        if variable is None:
            pu.print_error("Please specify a variable to read")
            return None

        evaluated = int(gdb.parse_and_eval(variable))
        log.info("pygdbpython.parse_variable(): evaluated variable = 0x%x" % evaluated)
        if self.get_size_sz() == 4:
            p = self.tohex(evaluated, 32)
        elif self.get_size_sz() == 8:
            p = self.tohex(evaluated, 64)
        return int(p, 16)

    def get_printed_variable(self, variable):
        if type(variable) == str:
            printed_var = '"%s"' % variable
        elif type(variable) == int:
            printed_var = "0x%x" % variable
        else:
            printed_var = variable
        return printed_var

    @gdb_is_running
    def read_variable(self, variable=None):
        """See debugger.py interface
        """

        printed_var = self.get_printed_variable(variable)
        log.debug(f"pygdbpython.read_variable({printed_var})")

        if variable is None:
            pu.print_error("Please specify a variable to read")
            return None

        try:
            variable = gdb.selected_frame().read_var(variable)
            log.debug(f"variable = {str(variable)}")
            return variable
        except RuntimeError as e:
            log.debug(f"exception 1: {e}")
            # No idea why this works but sometimes the frame is not selected
            # pu.print_error("No gdb frame is currently selected.\n")
            try:
                return gdb.selected_frame().read_var(variable)
            except RuntimeError as e:
                log.debug(f"exception 2: {e}")
                # variable was not found
                # pu.print_error("wrong here!")
                return None
        except ValueError as e:
            log.debug(f"exception 3: {e}")
            # variable was not found
            return None

    @gdb_is_running
    def read_variable_address(self, variable=None):
        """See debugger.py interface
        """

        printed_var = self.get_printed_variable(variable)
        log.debug(f"pygdbpython.read_variable_address({printed_var})")

        if variable is None:
            pu.print_error("Please specify a variable to read")
            return None

        try:
            variable = gdb.selected_frame().read_var(variable)
            log.debug(f"variable.address = {variable.address}")
            return variable.address
        except RuntimeError as e:
            log.debug(f"exception 1: {e}")
            # No idea why this works but sometimes the frame is not selected
            # pu.print_error("No gdb frame is currently selected.\n")
            try:
                variable = gdb.selected_frame().read_var(variable)
                return variable.address
            except RuntimeError as e:
                log.debug(f"exception 2: {e}")
                # variable was not found
                # pu.print_error("wrong here!")
                return None
        except (ValueError, AttributeError) as e:
            log.debug(f"exception 3: {e}")
            # variable was not found
            res = gdb.execute("x/x &{}".format(variable), to_string=True)
            return int(res.strip().split()[0], 16)

    @gdb_is_running
    def string_to_argv(self, arg=None):
        """XXX
        """

        log.debug("pygdbpython.string_to_argv()")

        if arg is not None:
            return gdb.string_to_argv(arg)

    @gdb_is_running
    def write_memory(self, address, buf, length=None):
        """See debugger.py interface
        """

        log.debug("pygdbpython.write_memory()")

        if self.inferior is None:
            self.inferior = self.get_inferior()

        try:
            if length is None:
                self.inferior.write_memory(address, buf)
            else:
                self.inferior.write_memory(address, buf, length)
        except MemoryError:
            pu.print_error("GDB inferior write_memory error")

    @gdb_is_running
    def search(
        self,
        start_address,
        end_address,
        search_value,
        search_type="string"
    ):
        """See debugger.py interface
        """

        log.debug("pygdbpython.search()")

        gdb_modifiers = {
            "byte": "b",
            "word": "h",
            "dword": "w",
            "qword": "g",
            "string": "b", # see below why
        }
        # We don't use find /s because it would assume a null terminator
        # so instead we convert into bytes
        if search_type == "string":
            search_value = ", ".join("0x{:02x}".format(ord(c)) for c in search_value)
        search_type = gdb_modifiers[search_type]
        cmd = "find /1%s 0x%x, 0x%x, %s" % (
            search_type,
            start_address,
            end_address,
            search_value,
        )
        log.debug(cmd)
        result = gdb.execute(cmd, from_tty=True, to_string=True)

        str_results = result.split("\n")
        for str_result in str_results:
            if str_result.startswith("0x"):
                return True

        return False

    @gdb_is_running
    def print_hexdump(self, address, size, unit=8):
        """See debugger.py interface
        """

        # See https://visualgdb.com/gdbreference/commands/x
        if unit == 1:
            #cmd = "x/%dbx 0x%x\n" % (size, address)
            try:
                mem = self.read_memory(address, size)
            except TypeError:
                pu.print_error("Invalid address specified")
                return
            except RuntimeError:
                pu.print_error("Could not read address {0:#x}".format(addr))
                return
            i = 0
            for line in hexdump.hexdump(bytes(mem), result='generator'):
                elts = line.split(":")
                txt = ":".join(elts[1:])
                print("0x%x: %s" % (address+i*0x10, txt))
                i += 1
            return
        elif unit == 2:
            cmd = "x/%dhx 0x%x\n" % (size/2, address)
        elif unit == 4:
            cmd = "x/%dwx 0x%x\n" % (size/4, address)
        elif unit == 8:
            cmd = "x/%dgx 0x%x\n" % (size/8, address)
        elif unit == "dps":
            # XXX - call into dps_like_for_gdb.py command for now
            # but we want to just add it to libptmalloc
            cmd = "dps 0x%x %d\n" % (address, size/self.get_size_sz())
        else:
            print("[!] Invalid unit specified")
            return
        print(self.execute(cmd, to_string=True))
        return

    def parse_address(self, addresses):
        """See debugger.py interface

        It should be able to handle gdb variables starting with $ or if we ommit it too
        """

        log.debug("pygdbpython.parse_address()")
        resolved = []
        if type(addresses) != list:
            addresses = [addresses]
        for item in addresses:
            addr = None
            try:
                # This should parse most cases like integers,
                # variables (exact name), registers (if we specify $ in front), as well
                # as arithmetic with integers, variables and registers.
                # i.e. as long as "p ABC" or "x /x ABC" works, it should work within here too
                addr = self.parse_variable(item)
                log.info("parsed address (default) = 0x%x" % addr)
            except:
                # XXX - Not sure what this is for?
                try:
                    addr = self.parse_variable("&" + item)
                    log.info("parsed address (unknown) = 0x%x" % addr)
                except:
                    # Parse registers if we don't specify the register, e.g. "rdi" instead of "$rdi"
                    try:
                        addr = self.parse_variable("$" + item)
                        log.info("parsed address (register) = 0x%x" % addr)
                    except:
                        pu.print_error(f"ERROR: Unable to parse {item}")
                        continue
            if addr is not None:
                resolved.append(addr)
        return resolved

    @gdb_is_running
    def get_libc_version(self):
        output = gdb.execute("info sharedlibrary libc.so", from_tty=True, to_string=True)
        if "No shared libraries matched." in output:
            return None
        for line in output.split("\n"):
            m = re.match("[0-9a-fx]+\s+[0-9a-fx]+\s+\w+\s+(.*)", line)
            if m:
                libc_path = m.group(1)
                log.info(f"found libc: \"{libc_path}\"")
                libc_path = Path(libc_path).resolve()
                log.info(f"resolved libc: \"{libc_path}\"")
                m = re.match("libc-(.*).so", libc_path.name)
                if m:
                    try:
                        libc_version = float(m.group(1))
                    except:
                        return None
                    log.info(f"found libc version: \"{libc_version}\"")
                    return libc_version
        return None

    @gdb_is_running
    def is_tcache_available(self):
        """See debugger.py interface

        An exception like below is raised on a glibc with tcache but if our program does not have actual threads to use tcache:
        ```
        (gdb) p tcache
        Cannot find thread-local storage for process 117994, shared library /usr/lib/debug/lib/x86_64-linux-gnu/libc-2.27.so:
        Cannot find thread-local variables on this target
        ```
        """
        try:
            output = gdb.execute("p tcache", from_tty=True, to_string=True)
        except gdb.error:
            return False
        return True

    #
    # gdb-specific methods
    #

    @gdb_is_running
    def get_arch(self):
        """Retrieve the architecture
        """
        log.debug("pygdbpython.get_arch()")

        cmd = self.execute("maintenance info sections ?")
        return cmd.strip().split()[-1:]

    def get_inferior(self):
        """Get the gdb inferior, used for other gdb commands
        """

        log.debug("pygdbpython.get_inferior()")
        try:
            if self.inferior is None:
                if len(gdb.inferiors()) == 0:
                    pu.print_error("No gdb inferior could be found.")
                    return -1
                else:
                    self.inferior = gdb.inferiors()[0]
                    return self.inferior
            else:
                return self.inferior
        except AttributeError:
            pu.print_error("This gdb's python support is too old.")
            raise Exception("sys.exit()")

    # XXX - move to generic helper shared by all debuggers?
    def tohex(self, val, nbits):
        """Handle gdb adding extra char to hexadecimal values
        """

        log.debug("pygdbpython.tohex()")
        result = hex((val + (1 << nbits)) % (1 << nbits))
        # -1 because hex() only sometimes tacks on a L to hex values...
        if result[-1] == "L":
            return result[:-1]
        else:
            return result

    @gdb_is_running
    def get_backtrace(self):
        """See debugger.py interface
        """

        log.debug("pygdbpython.get_backtrace()")
        d = {}
        output = self.execute("backtrace")
        d["raw"] = output
        funcs = []
        lines = output.split("\n")
        for i in range(len(lines)):
            # This is shown when "set verbose on" was executed so skip those
            if "Reading in symbols" in lines[i]:
                continue
            else:
                lines = lines[i:]
                break
        if lines[0].startswith("#0"):
            for line in lines:
                if not line:
                    continue
                log.debug(f"Handling: '{line}'")
                elts = line.split()
                if len(elts) < 3:
                    pu.print_error("Skipping too small line in backtrace")
                    continue
                if not elts[0].startswith("#"):
                    pu.print_error("Skipping non-valid line in backtrace")
                    continue
                if elts[2] == "in":
                    # Something like:
                    # #1  0x00007f834a8c8190 in _nl_make_l10nflist (l10nfile_list=...) at ../intl/l10nflist.c:237
                    funcs.append(elts[3])
                else:
                    # Something like:
                    # #0  __GI___libc_free (mem=...) at malloc.c:3096
                    funcs.append(elts[1])

        d["funcs"] = funcs
        return d
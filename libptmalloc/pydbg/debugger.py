import importlib

import libptmalloc.frontend.helpers as h
importlib.reload(h)

class pydbg:
    """Python abstraction interface that allows calling into any specific debugger APIs

    Any debugger implementation should implement the methods called on self.debugger
    """
    
    def __init__(self, debugger):
        """Initialize the debugger to be used for any future API
        """
        self.debugger = debugger

    def execute(self, cmd, to_string=True):
        """Execute a command in the debugger CLI
        """
        return self.debugger.execute(cmd, to_string=to_string)

    def format_address(self, value):
        """XXX"""
        return self.debugger.format_address(value)

    def get_heap_address(self, par=None):
        """XXX"""
        return self.debugger.get_heap_address(par)

    def get_size_sz(self):
        """Retrieve the size_t size for the current architecture
        """
        return self.debugger.get_size_sz()

    def read_memory(self, address, length):
        """Read bytes at the given address of the given length
        """
        return self.debugger.read_memory(address, length)

    def parse_variable(self, variable):
        """Parse and evaluate a debugger variable expression
        """
        return self.debugger.parse_variable(variable)

    def read_variable(self, variable):
        """Read the value stored at the variable name or address"""
        return self.debugger.read_variable(variable)

    def read_variable_address(self, variable):
        """Gets the variable name's address"""
        return self.debugger.read_variable_address(variable)

    def string_to_argv(self, arg):
        """XXX"""
        return self.debugger.string_to_argv(arg)

    def write_memory(self, address, buf, length=None):
        """Write bytes from buf at the given address in memory
        """
        return self.debugger.write_memory(address, buf, length)

    def search_chunk(self, ptm, p, search_value, search_type, depth=0, skip=False):
        """Searches a chunk for a specific value of a given type
        Includes the chunk header in the search by default

        :param ptm: ptmalloc object
        :param p: malloc_chunk object representing the chunk
        :param search_value: string representing what to search for
        :param search_type: "byte", "word", "dword", "qword" or "string"
        :param depth: How far into each chunk to search, starting from chunk header address
        :param skip: True if don't include chunk header contents in search results
        :return: True if the value was found, False otherwise

        Note: this method is generic and does not need a debugger-specific implementation
        """
        if depth == 0 or depth > ptm.chunksize(p):
            depth = ptm.chunksize(p)

        start_address = p.address
        if skip:
            start_address += p.hdr_size
        try:
            result = self.search(
                start_address, p.address + depth, search_value, search_type=search_type
            )
            return result
        except Exception:
            print("WARNING: search failed")
            h.show_last_exception()
            return False

    def search(
        self, start_address, end_address, search_value, search_type="string"
    ):
        """Find a value within some address range

        :param start_address: where to start searching
        :param end_address: where to end searching
        :param search_value: string representing what to search for
        :param search_type: "byte", "word", "dword", "qword" or "string"
        :return: True if the value was found, False otherwise
        """
        return self.debugger.search(
            start_address, end_address, search_value, search_type=search_type
        )

    def parse_address(self, addresses):
        """Parse one or more addresses or debugger variables

        :param address: an address string containing hex, int, or debugger variable
        :return: the resolved addresses as integers

        It this should be able to handle: hex, decimal, program variables
        with or without special characters (like $, &, etc.),
        basic addition and subtraction of variables, etc.
        """
        return self.debugger.parse_address(addresses)

    def get_backtrace(self):
        """Get the current backtrace returned in a dictionary such as:
        
        {
            "raw": "...raw backtrace retured by the debugger"
            "funcs": ["list", "of", "functions"]
        }
        """
        return self.debugger.get_backtrace()

    def get_libc_version(self):
        """Retrieve the glibc version if possible as a float (e.g. 2.27) or None if unknown
        """
        return self.debugger.get_libc_version()


    def print_hexdump_chunk(self, ptm, p, maxlen=0, off=0, debug=False, unit=8, verbose=1):
        """Hexdump chunk data to stdout
        
        :param ptm: ptmalloc object
        :param p: malloc_chunk() object representing the chunk
        :param maxlen: maximum amount of bytes to hexdump
        :param off: offset into the chunk's data to hexdump (after the malloc_chunk header)
        :param debug: debug enabled or not
        :param unit: hexdump unit (e.g. 1, 2, 4, 8, "dps")
        :param verbose: see ptchunk's ArgumentParser definition
        """

        address = p.address + p.hdr_size + off
        size = ptm.chunksize(p) - p.hdr_size - off
        if size <= 0:
            if p.inuse:
                print("[!] Chunk corrupt? Bad size")
                return
            else:
                if debug:
                    print("<old chunk contents merged with free header>")
                return
        # ptmalloc can optimize chunks contents and sizes since the a prev_size field is not used 
        # when the previous chunk is allocated, so ptmalloc can use the extra 8 bytes in 64-bit 
        # or 4 bytes in 32-bit to hold user content. We allow to show it with -vv
        real_size = size
        if verbose >= 2:
            real_size += self.get_size_sz()
        if real_size > size:
            print("0x%x+0x%x bytes of chunk data:" % (size, real_size-size))
        else:
            print("0x%x bytes of chunk data:" % real_size)
        shown_size = real_size
        if maxlen != 0:
            if shown_size > maxlen:
                shown_size = maxlen

        self.print_hexdump(address, shown_size, unit=unit)
        if verbose >= 2 and shown_size > size:
            print("INFO: the following chunk prev_size field is shown above as could contain user data (ptmalloc optimization)")

    def print_hexdump(self, address, size, unit=8):
        """Hexdump data to stdout

        :param address: starting address
        :param size: number of bytes from the address
        :param unit: hexdump unit (e.g. 1, 2, 4, 8, "dps")
        """

        self.debugger.print_hexdump(address, size, unit=unit)

    def is_tcache_available(self):
        """Check if tcache is available by looking up global "tcache" symbol.

        Sometimes, even though glibc has tcache enabled, "tcache" symbol is not available and it seems
        tcache is not used because no additional thread is created (?)
        """
        return self.debugger.is_tcache_available()

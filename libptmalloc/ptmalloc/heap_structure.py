# -*- coding: future_fstrings -*-
import logging
import struct

log = logging.getLogger("libptmalloc")
log.trace("heap_structure.py")

class heap_structure(object):
    """Represent a general structure. Can be inherited by any structure like malloc_chunk.
    Allow factoring of functions used by many structures, so we don't duplicate code.
    """

    def __init__(self, ptm, debugger=None):
        """XXX
        """

        log.trace("heap_structure.__init__()")
        self.ptm = ptm
        self.is_x86 = self.ptm.SIZE_SZ == 4 # XXX - actually use that or delete?
        self.initOK = True
        self.address = None
        self.mem = None
        self.dbg = debugger

    def validate_address(self, address):
        """Valid that a given address can actually be used as chunk address
        """
        log.trace("heap_structure.validate_address()")

        if address is None or address == 0 or type(address) != int:
            print("Invalid address")
            #raise Exception("Invalid address")
            self.initOK = False
            self.address = None
            return False
        else:
            self.address = address
        return True

    def unpack_variable(self, fmt, offset):
        return struct.unpack_from(fmt, self.mem, offset)[0]
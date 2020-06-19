class heap_structure(object):

    """Docstring for heap_structure. """

    def __init__(self, ptm, debugger=None):
        """TODO: to be defined. """
        self.ptm = ptm
        self.is_x86 = self.ptm.SIZE_SZ == 4
        self.initOK = True
        self.address = None
        self.debugger = debugger

    #        if is_gdb and inferior == None:
    #            self.inferior = hgdb.get_inferior()
    #            if self.inferior == -1:
    #                self.pt.logmsg("Error obtaining gdb inferior")
    #                self.initOK = False
    #                return
    #        else:
    #            self.inferior = inferior

    # XXX - all functions below should be part of the actual debugger/gdb stuff

    def _get_cpu_register(self, reg):
        """
        Get the value holded by a CPU register
        """

        expr = ""
        if reg[0] == "$":
            expr = reg
        else:
            expr = "$" + reg

        try:
            val = self._normalize_long(long(self.debugger.parse_and_eval(expr)))
        except Exception:
            print("Have you run the process? Can't retrieve registers")
            return None
        return val

    def _normalize_long(self, l):
        return (0xFFFFFFFF if self.is_x86 else 0xFFFFFFFFFFFFFFFF) & l

    def _is_register(self, s):
        """
        bin_size Is it a valid register ?
        """
        x86_reg = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip"]
        x64_reg = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip"] + [
            "r%d" % i for i in range(8, 16)
        ]

        if s[0] == "$":
            s = s[1:]

        if s in (x86_reg if self.is_x86 else x64_reg):
            return True
        return False

    def _parse_base_offset(self, r):
        base = r
        offset = 0
        if "+" in r:
            # we assume it is a register or address + a hex value
            tmp = r.split("+")
            base = tmp[0]
            offset = int(tmp[1], 16)
        if "-" in r:
            # we assume it is a register or address - a hex value
            tmp = r.split("-")
            base = tmp[0]
            offset = int(tmp[1], 16) * -1
        if self._is_register(base):
            base = self._get_cpu_register(base)
            if not base:
                return None
        else:
            try:
                # we assume it's an address
                base = int(base, 16)
            except Exception:
                print("Error: not an address")
                return None
        return base, offset

    def validate_address(self, address):
        """Valid that a given address can actually be used as chunk"""
        if address is None or address == 0:
            print("[libptmalloc] invalid address")
            self.initOK = False
            self.address = None
            return False
        elif type(address) == str:
            res = self._parse_base_offset(address)
            if res is None:
                self.pt.logmsg(
                    'First arg MUST be either an address or a register (+ optional offset)"'
                )
                self.initOK = False
                return False
            self.address = res[0] + res[1]
        else:
            self.address = address
        return True

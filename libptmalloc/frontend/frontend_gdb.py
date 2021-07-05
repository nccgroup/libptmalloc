# -*- coding: future_fstrings -*-
import logging

log = logging.getLogger("libptmalloc")
log.trace(f"frontend_gdb.py")

from libptmalloc.frontend.commands.gdb import ptfast
from libptmalloc.frontend.commands.gdb import pthelp
from libptmalloc.frontend.commands.gdb import ptlist
from libptmalloc.frontend.commands.gdb import ptstats
from libptmalloc.frontend.commands.gdb import ptchunk
from libptmalloc.frontend.commands.gdb import ptfree
from libptmalloc.frontend.commands.gdb import ptbin
from libptmalloc.frontend.commands.gdb import ptarena
from libptmalloc.frontend.commands.gdb import ptparam
from libptmalloc.frontend.commands.gdb import ptmeta
from libptmalloc.frontend.commands.gdb import ptconfig
from libptmalloc.frontend.commands.gdb import pttcache

class frontend_gdb:
    """Register commands with GDB"""

    def __init__(self, ptm):

        # We share ptm (globals as well as cached info (such as the mstate))
        # among all commands below

        # The below dictates in what order they will be shown in gdb
        cmds = []
        cmds.append(ptconfig.ptconfig(ptm))
        cmds.append(ptmeta.ptmeta(ptm))
        cmds.append(ptarena.ptarena(ptm))
        cmds.append(ptparam.ptparam(ptm))
        cmds.append(ptlist.ptlist(ptm))
        cmds.append(ptchunk.ptchunk(ptm))
        cmds.append(ptbin.ptbin(ptm))
        cmds.append(ptfast.ptfast(ptm))
        cmds.append(pttcache.pttcache(ptm))
        cmds.append(ptfree.ptfree(ptm))
        cmds.append(ptstats.ptstats(ptm))

        pthelp.pthelp(ptm, cmds)

        output = ptm.dbg.execute("ptconfig")
        print(output)

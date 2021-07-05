import logging
import importlib

log = logging.getLogger("libptmalloc")
log.trace(f"frontend_gdb.py")

import libptmalloc.frontend.commands.gdb.ptfast as ptfast
importlib.reload(ptfast)
import libptmalloc.frontend.commands.gdb.pthelp as pthelp
importlib.reload(pthelp)
import libptmalloc.frontend.commands.gdb.ptlist as ptlist
importlib.reload(ptlist)
import libptmalloc.frontend.commands.gdb.ptstats as ptstats
importlib.reload(ptstats)
import libptmalloc.frontend.commands.gdb.ptchunk as ptchunk
importlib.reload(ptchunk)
import libptmalloc.frontend.commands.gdb.ptfree as ptfree
importlib.reload(ptfree)
import libptmalloc.frontend.commands.gdb.ptbin as ptbin
importlib.reload(ptbin)
import libptmalloc.frontend.commands.gdb.ptarena as ptarena
importlib.reload(ptarena)
import libptmalloc.frontend.commands.gdb.ptparam as ptparam
importlib.reload(ptparam)
import libptmalloc.frontend.commands.gdb.ptmeta as ptmeta
importlib.reload(ptmeta)
import libptmalloc.frontend.commands.gdb.ptconfig as ptconfig
importlib.reload(ptconfig)
import libptmalloc.frontend.commands.gdb.pttcache as pttcache
importlib.reload(pttcache)

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

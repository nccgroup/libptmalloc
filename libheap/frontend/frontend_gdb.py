from libheap import ptmalloc
from libheap.frontend.commands.gdb.fastbins import fastbins
from libheap.frontend.commands.gdb.freebins import freebins
from libheap.frontend.commands.gdb.heap import heap
from libheap.frontend.commands.gdb.heapls import heapls
from libheap.frontend.commands.gdb.heaplsc import heaplsc
from libheap.frontend.commands.gdb.mstats import mstats
from libheap.frontend.commands.gdb.print_bin_layout import print_bin_layout
from libheap.frontend.commands.gdb.ptchunk import ptchunk
from libheap.frontend.commands.gdb.smallbins import smallbins


class frontend_gdb:
    """Register commands with GDB"""

    def __init__(self, debugger, version):
        ptm = ptmalloc.ptmalloc.ptmalloc(debugger=debugger)

        heap(ptm, debugger, version)
        mstats(ptm, debugger, version)
        heapls(ptm, debugger, version)
        heaplsc(ptm, debugger, version)
        fastbins(ptm, debugger, version)
        freebins(ptm, debugger, version)
        smallbins(ptm, debugger, version)
        print_bin_layout(ptm, debugger, version)
        ptchunk(ptm, debugger, version)

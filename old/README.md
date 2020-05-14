# libptmalloc

**libptmalloc** is a python script designed for use with GDB that can be used to
analyse the per-threaded fork of the Doug Lea allocator, aka ptmalloc. It
currently supports ptmalloc2 only. Note that some parts can also be used
independently GDB, for instance to do offline analysis of some snapshotted heap
memory.

libptmalloc is a fork of [libheap](https://github.com/cloudburst/libheap), with
modifications to make its commands more like
[libdlmalloc](https://github.com/nccgroup/libdlmalloc) and [libdlmalloc](https://github.com/nccgroup/libdlmalloc) 

We are aware that libheap, gef, and pwndbg all contain their own good code to
analyze ptmalloc2 structures. This is not a perfect replacement for any of
them, but served our needs. 

## Supported versions

libptmalloc has been heavily tested with recent 64-bit Cisco ASA versions (both
ASA5500-X series and GNS3) that use glibc's ptmalloc2-based allocator. Also
note that some old 64-bit ASA versions actually use dlmalloc. You can refer to
this
[table](https://github.com/nccgroup/asafw/blob/master/README.md#mitigation-summary)
for a list of the versions using ptmalloc2 if you plan to use it on one of
these devices.

We have done some testing of libptmalloc on 32-bit, but much less than 64-bit.
Also as noted above, it only works with ptmalloc2. It will not work on ptmalloc
and ptmalloc3 due to differing heap structures.

## Installation

The script just requires a reliatiely modern version of GDB with python3
support. We have primarily tested on python3, so we expect it will break on
python2.7 atm.

If you want to use the gdb commands you can use:

```
    (gdb) source libptmalloc2.py
```

A bunch of the core logic is broken out into the pt_helper class, which allows
you to directly import libptmalloc2.py and access certain important structures outside of
a GDB session. This is useful if you want to analyze offline chunk/heap
snapshots.

# Usage

Most of the functionality is modelled after the approach in unmask_jemalloc and
libtalloc where a separate GDB command is provided. Though we do also use a
fair number of switches.

## pthelp

This is the main function to view the available commands. Each of the commands
supports the `-h` option which allows you to obtain more detailed usage
instructions.

```
(gdb) pthelp
[libptmalloc] ptmalloc commands for gdb
[libptmalloc] ptchunk    : show chunk contents (-v for verbose, -x for data dump)
[libptmalloc] ptsearch   : search heap for hex value or address
[libptmalloc] ptarena    : print mstate struct. caches address after first use
[libptmalloc] ptcallback : register a callback or query/modify callback status
[libptmalloc] pthelp     : this help message
[libptmalloc] NOTE: Pass -h to any of these commands for more extensive usage. Eg: ptchunk -h
```

## Chunk analysis

`ptchunk` can provide you with a summary of a chunk, or more verbose
information of every field. You can also use it to list information about
multiple chunks,etc. One limitation it currently has is that it kUsage for ptchunk can be seen below:


The `ptchunk` command is used to show information related to a chunk.

```
(gdb) ptchunk -h
[libptmalloc] usage: ptchunk [-v] [-f] [-x] [-c <count>] [-s <val] [--depth <depth>] <addr>
[libptmalloc]  -v      use verbose output (multiples for more verbosity)
[libptmalloc]  -f      use <addr> explicitly, rather than be smart
[libptmalloc]  -x      hexdump the chunk contents
[libptmalloc]  -m      max bytes to dump with -x
[libptmalloc]  -c      number of chunks to print
[libptmalloc]  -s      search pattern when print chunks
[libptmalloc]  --depth how far into each chunk to search
[libptmalloc]  -d     debug and force printing stuff
[libptmalloc]  <addr>  a ptmalloc chunk header
[libptmalloc] Flag legend: P=PREV_INUSE, M=MMAPPED, N=NON_MAIN_ARENA
```

Basic chunk output looks like the following:

```
(gdb) ptchunk 0x55555e8aeda0
0x55555e8aeda0 M sz:0x00060 fl:--P
```

We provide the exact address of the chunks metadata, not the data it holds. We
can get more verbose output using the `-v` switch:

```
(gdb) ptchunk -v 0x55555e8aeda0
struct malloc_chunk @ 0x55555e8aeda0 {
prev_size   = 0x0
size        = 0x60 (PREV_INUSE)
```

You can list multiple chunks using the `-c` switch.

```
(gdb) ptchunk -c 5 0x55555e8aecb0
0x55555e8aecb0 f sz:0x00070 fl:---
0x55555e8aed20 f sz:0x00080 fl:--P
0x55555e8aeda0 M sz:0x00060 fl:--P
0x55555e8aee00 M sz:0x00060 fl:--P
0x55555e8aee60 M sz:0x00060 fl:--P
```

You can also see the contents of chunks using `-x`. You can also limit the
number of bytes you dump using `-m`:

```
(gdb) ptchunk -x 0x55555e98d9a0
0x55555e98d9a0 M sz:0x00070 fl:--P alloc_pc:0x555556338c75,-
0x60 bytes of chunk data:
0x55555e98d9b0:	0xa11c0123	0x00000030	0x00010000	0x00000000
0x55555e98d9c0:	0x5e988be0	0x00005555	0x5e98dbd0	0x00005555
0x55555e98d9d0:	0x56338c75	0x00005555	0x00000000	0x00000000
0x55555e98d9e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55555e98d9f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55555e98da00:	0x00000000	0x00000000	0x00006168	0x00000000
(gdb) ptchunk -x -m 16 0x55555e98d9a0
0x55555e98d9a0 M sz:0x00070 fl:--P
0x10 bytes of chunk data:
0x55555e98d9b0:	0xa11c0123	0x00000030	0x00010000	0x00000000
```

We can use also search for specific values inside of chunks we're looking at by
using the `-s` switch. How far into the chunk we search can be dictated by the
`--depth` switch. For example:

```
(gdb) ptchunk -x 0x55555e8aecb0
0x55555e8aecb0 f sz:0x00070 fl:---
0x58 bytes of chunk data:
0x55555e8aecc0:	0x5ea5f960	0x00005555	0x0001ffff	0x00000000
0x55555e8aecd0:	0x5e89ed30	0x00005555	0x5e8c34b0	0x00005555
0x55555e8aece0:	0x56338c75	0x00005555	0x563383ed	0x00005555
0x55555e8aecf0:	0x00000000	0x00000000	0x00000000	0x00000000
0x55555e8aed00:	0x00000000	0x00000000	0x00000000	0x00000000
0x55555e8aed10:	0x00000000	0x00000000
(gdb) ptchunk -c 5 -s 0x0001ffff 0x55555e8aecb0
0x55555e8aecb0 f sz:0x00070 fl:-- [MATCH]
0x55555e8aed20 f sz:0x00080 fl:-- [MATCH]
0x55555e8aeda0 M sz:0x00060 fl:-- [NO MATCH]
0x55555e8aee00 M sz:0x00060 fl:-- [NO MATCH]
0x55555e8aee60 M sz:0x00060 fl:-- [NO MATCH]
(gdb) ptchunk -c 5 -s 0x0001ffff --depth 8 0x55555e8aecb0
0x55555e8aecb0 f sz:0x00070 fl:-- [NO MATCH]
0x55555e8aed20 f sz:0x00080 fl:-- [NO MATCH]
0x55555e8aeda0 M sz:0x00060 fl:-- [NO MATCH]
0x55555e8aee00 M sz:0x00060 fl:-- [NO MATCH]
0x55555e8aee60 M sz:0x00060 fl:-- [NO MATCH]
```

## Arena analysis

The `ptarena` command can be used to analyze one or more arenas.

```
(gdb) ptarena -h
[libptmalloc] usage: ptarena [-v] [-f] [-x] [-c <count>] <addr>
[libptmalloc]  <addr> a ptmalloc mstate struct. Optional with cached mstate
[libptmalloc]  -v     use verbose output (multiples for more verbosity)
[libptmalloc]  -l     list arenas only
[libptmalloc]  NOTE: Last defined mstate will be cached for future use
```

We can take a look at an arena, by pulling the `main_arena` symbol from
`glibc.so`:

```
(gdb) ptarena 0x7ffff4c9b620
struct malloc_mstate {
mutex          = 0x0
flags          = 0x0
fastbinY[0] = 0x0
fastbinY[1] = 0x0
fastbinY[2] = 0x0
fastbinY[3] = 0x0
fastbinY[4] = 0x0
fastbinY[5] = 0x55555e8aecb0
fastbinY[6] = 0x55555e8aed20
fastbinY[7] = 0x0
fastbinY[8] = 0x0
fastbinY[9] = 0x0
top            = 0x55555ea644d0
last_remainder = 0x55555e8b3020
bin[0]:     = 0x55555ea62860, 0x55555e979ad0
bin[1]:     = 0x55555e920420, 0x55555e6363d0
bin[2]:     = 0x55555e641010, 0x55555e63cdc0
bin[3]:     = 0x7ffff4c9b6a8, 0x7ffff4c9b6a8
bin[4]:     = 0x7ffff4c9b6b8, 0x7ffff4c9b6b8
bin[5]:     = 0x55555ea62a70, 0x55555ea62a70
bin[6]:     = 0x7ffff4c9b6d8, 0x7ffff4c9b6d8
bin[7]:     = 0x7ffff4c9b6e8, 0x7ffff4c9b6e8
bin[8]:     = 0x7ffff4c9b6f8, 0x7ffff4c9b6f8
bin[9]:     = 0x55555e9254a0, 0x55555e9254a0
bin[10]:    = 0x7ffff4c9b718, 0x7ffff4c9b718
bin[11]:    = 0x55555e78a7f0, 0x55555e78a7f0
bin[12]:    = 0x7ffff4c9b738, 0x7ffff4c9b738
bin[13]:    = 0x7ffff4c9b748, 0x7ffff4c9b748
bin[14]:    = 0x55555e926c70, 0x55555e926c70
bin[15]:    = 0x7ffff4c9b768, 0x7ffff4c9b768
[SNIP]
bin[51]:    = 0x7ffff4c9b9a8, 0x7ffff4c9b9a8
bin[52]:    = 0x55555e988db0, 0x55555e988db0
bin[53]:    = 0x7ffff4c9b9c8, 0x7ffff4c9b9c8
bin[54]:    = 0x7ffff4c9b9d8, 0x7ffff4c9b9d8
bin[55]:    = 0x7ffff4c9b9e8, 0x7ffff4c9b9e8
bin[56]:    = 0x7ffff4c9b9f8, 0x7ffff4c9b9f8
bin[57]:    = 0x7ffff4c9ba08, 0x7ffff4c9ba08
bin[58]:    = 0x7ffff4c9ba18, 0x7ffff4c9ba18
bin[59]:    = 0x7ffff4c9ba28, 0x7ffff4c9ba28
bin[60]:    = 0x7ffff4c9ba38, 0x7ffff4c9ba38
bin[61]:    = 0x7ffff4c9ba48, 0x7ffff4c9ba48
bin[62]:    = 0x7ffff4c9ba58, 0x7ffff4c9ba58
bin[63]:    = 0x7ffff4c9ba68, 0x7ffff4c9ba68
bin[64]:    = 0x55555e94f1c0, 0x55555ea1e2b0
bin[65]:    = 0x7ffff4c9ba88, 0x7ffff4c9ba88
bin[66]:    = 0x7ffff4c9ba98, 0x7ffff4c9ba98
bin[67]:    = 0x7ffff4c9baa8, 0x7ffff4c9baa8
bin[68]:    = 0x7ffff4c9bab8, 0x7ffff4c9bab8
bin[69]:    = 0x7ffff4c9bac8, 0x7ffff4c9bac8
bin[70]:    = 0x7ffff4c9bad8, 0x7ffff4c9bad8
bin[71]:    = 0x7ffff4c9bae8, 0x7ffff4c9bae8
bin[72]:    = 0x55555e987f10, 0x55555e94f990
bin[73]:    = 0x7ffff4c9bb08, 0x7ffff4c9bb08
bin[74]:    = 0x7ffff4c9bb18, 0x7ffff4c9bb18
bin[75]:    = 0x7ffff4c9bb28, 0x7ffff4c9bb28
bin[76]:    = 0x7ffff4c9bb38, 0x7ffff4c9bb38
bin[77]:    = 0x7ffff4c9bb48, 0x7ffff4c9bb48
[SNIP]
bin[126]:   = 0x7ffff4c9be58, 0x7ffff4c9be58
binmap[0]   = 0x48947c
binmap[1]   = 0x200004
binmap[2]   = 0x202
binmap[3]   = 0x0
next           = 0x7fffa4000020
next_free      = 0x0
system_mem     = 0x444000
max_system_mem = 0x444000
```

We can also dump all of the arenas referenced by this arena:

```
(gdb) ptarena 0x7ffff4c9b620 -l
Arena(s) found:
	 arena @ 0x7ffff4c9b620
	 arena @ 0x7fffa4000020
	 arena @ 0x7fffb0000020
	 arena @ 0x7fffac000020
	 arena @ 0x7fffb8000020
	 arena @ 0x7fffb4000020
	 arena @ 0x7fffc0000020
	 arena @ 0x7fffbc000020
	 arena @ 0x7fffc8000020
	 arena @ 0x7fffc4000020
	 arena @ 0x7fffcc000020
	 arena @ 0x7fffd0000020
	 arena @ 0x7fffd8000020
```

## Heap searching

libptmalloc includes a gdb command that lets you search across all known arenas
for some specific values. Currently usage is just available by supplying no
arguments:

```
[libptmalloc] usage: ptsearch -a <arena> <hex> <min_size> <max_size>
```

This is a command that let us search for values in each chunk across all
arenas. Naturally it can be quite slow, especially over serial which is the case
when analyzing real Cisco ASA devices. It relies on a cached arena address (set 
with  `ptarena` command) and it will parse all arenas linked to the one that is 
cached. An example of searching for the value 0xa11c0123.

```
(gdb) ptsearch 0xa11c0123
[libptmalloc] Handling arena @ 0x7fffa4000020
[libptmalloc] chunk with zero size detected at 0x7fffa4021000
[libptmalloc] sz=0x0 detected at 0x7fffa4021000, assuming end of heap
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffa40008b0
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffa4000930
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffa40009a0
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffa4000a10
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffa4000a60
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffa4000ab0
[libptmalloc] Handling arena @ 0x7fffb0000020
[libptmalloc] chunk with zero size detected at 0x7fffb0021000
[libptmalloc] sz=0x0 detected at 0x7fffb0021000, assuming end of heap
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffb00008b0
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffb0000930
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffb0000990
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffb0000a30
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffb0000d00
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffb0000d50
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffb0000e20
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffb0000f00
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffb0000f70
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffb0001330
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffb0003370
[libptmalloc] 0xa11c0123 found in chunk at 0x7fffb00053b0
[libptmalloc] Handling arena @ 0x7fffac000020
[...]
```
## ptcallback

This is a command that allows you to register a callback that can help annotate
additional structures that might be contained inside of a chunk. In our case we
use this to typically show Cisco ASA mempool headers.

```
(gdb) ptcallback -h
[libptmalloc] usage: ptcallback <options>
[libptmalloc]  disable         temporarily disable the registered callback
[libptmalloc]  enable          enable the registered callback
[libptmalloc]  status          check if a callback is registered
[libptmalloc]  clear           forget the registered callback
[libptmalloc]  register <name> use a global function <name> as callback
[libptmalloc]  register <name> <module> use a global function <name> as callback from <module>
```

An example of using most of the functionality is shown below. We first register
the callback but disable it:

```
(gdb) ptcallback status
[libptmalloc] a callback is not registered
(gdb) ptcallback register mpcallback libmempool/libmempool
[libmempool] loaded
[libptmalloc] mpcallback registered as callback
(gdb) ptcallback status
[libptmalloc] a callback is registered and enabled
(gdb) ptcallback disable
[libptmalloc] callback disabled
(gdb) ptcallback status
[libptmalloc] a callback is registered and disabled
```

With the callback disabled, it only shows the ptmalloc chunk header:

```
(gdb) ptchunk -v 0x55555e98d9a0
struct malloc_chunk @ 0x55555e98d9a0 {
prev_size   = 0xa11ccdef
size        = 0x70 (PREV_INUSE)
```

Now we enable the callback and again display metadata. We see it shows the
`mp_header` in addition to the ptmalloc chunk header:

```
(gdb) ptcallback enable
[libptmalloc] callback enabled
(gdb) ptchunk -v 0x55555e98d9a0
struct malloc_chunk @ 0x55555e98d9a0 {
prev_size   = 0xa11ccdef
size        = 0x70 (PREV_INUSE)
struct mp_header @ 0x55555e98d9b0 {
mh_magic      = 0xa11c0123
mh_len        = 0x30
mh_refcount   = 0x10000
mh_unused     = 0x0
mh_fd_link    = 0x55555e988be0 (OK)
mh_bk_link    = 0x55555e98dbd0 (OK)
alloc_pc      = 0x555556338c75 (-)
free_pc       = 0x0 (-)
```

We can also completely clear the callback:

```
(gdb) ptcallback clear
[libptmalloc] callback cleared
(gdb) ptchunk -v 0x55555e98d9a0
struct malloc_chunk @ 0x55555e98d9a0 {
prev_size   = 0xa11ccdef
size        = 0x70 (PREV_INUSE)
```

## Callback dict

This works in the same was as in our libdlmalloc plugin. We send a dict
containing a lot of information to a callback function and it can choose to do
whatever it wants to with the information. We provide more information than
most callbacks will need. Also the expectation is that the callback will likely
need to be aware of the plugin issuing the callback, in order for it to inform
what additional information it will show.  On the flip side, the plugin
(libdlmalloc in this case) calling into the callback doesn't currently need to
know (or care) about anything that the this external callback provider does.

An example of some of the data we provide to the callback function is:

* `caller`: name of calling gdb command or function
* `allocator`: backing allocator that manages the chunk address we send
* `addr`: address of the chunk contents after the core alloctor's metadata
* `hdr_sz`: size of the core allocator's metadata header
* `chunksz`: size of the chunk according to the core allocators metadata header
* `min_hdr_sz`: the minimum header size possible for this core allocator
* `data_size`: size of the data at `addr`
* `inuse`: whether a chunk is inuse according to the core allocator
* `chunk_info`: whether or not the calling library is printing chunk info
* `size_sz`: The calculated size of a `size_t` data type on the debugged platform

# Future development

We will likely add functionality to libptmalloc as we need or while doing
future Cisco ASA research. Planned additions currently are:

- Abstract out the debug engine logic to be more like libheap or shadow's newer
  designs
- We may consider integration into some other popular ptmalloc plugin rather
  than maintaining our own tool

# Contact

We would love to hear feedback about this tool and also are happy to get pull
requests.

* Aaron Adams
    * Email: `aaron<dot>adams<at>nccgroup<dot>trust`
    * Twitter: @fidgetingbits

* Cedric Halbronn
    * Email: `cedric<dot>halbronn<at>nccgroup<dot>trust`
    * Twitter: @saidelike

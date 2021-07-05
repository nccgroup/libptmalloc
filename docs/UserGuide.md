<!-- vim-markdown-toc GFM -->

* [Usage](#usage)
    * [libptmalloc commands](#libptmalloc-commands)
    * [Commands' usage](#commands-usage)
* [Common usage and example](#common-usage-and-example)
    * [ptconfig](#ptconfig)
    * [ptarena](#ptarena)
    * [ptlist](#ptlist)
    * [ptchunk](#ptchunk)
        * [Allocated chunk](#allocated-chunk)
        * [Free chunk in regular bin](#free-chunk-in-regular-bin)
        * [Printing multiple chunks](#printing-multiple-chunks)
        * [Combining options](#combining-options)
    * [ptbin](#ptbin)
    * [ptfast](#ptfast)
    * [pttcache](#pttcache)
    * [ptfree](#ptfree)
    * [ptstats](#ptstats)
    * [ptmeta](#ptmeta)
* [Cache](#cache)
* [Advanced usage](#advanced-usage)
    * [Searching chunks](#searching-chunks)
    * [Printing chunks of specific type(s)](#printing-chunks-of-specific-types)
* [Detailed commands' usage](#detailed-commands-usage)
    * [ptconfig usage](#ptconfig-usage)
    * [ptmeta usage](#ptmeta-usage)
    * [ptarena usage](#ptarena-usage)
    * [ptparam usage](#ptparam-usage)
    * [ptlist usage](#ptlist-usage)
    * [ptchunk usage](#ptchunk-usage)
    * [ptbin usage](#ptbin-usage)
    * [ptfast usage](#ptfast-usage)
    * [pttcache usage](#pttcache-usage)
    * [ptfree usage](#ptfree-usage)
    * [ptstats usage](#ptstats-usage)
* [Comparison with other tools](#comparison-with-other-tools)
    * [libheap](#libheap)
* [Notes](#notes)

<!-- vim-markdown-toc -->

# Usage

## libptmalloc commands

The `pthelp` command lists all the commands provided by libptmalloc:

```
(gdb) pthelp
pthelp              List all libptmalloc commands
ptconfig            Show/change ptmalloc configuration
ptmeta              Handle metadata associated with chunk addresses
ptarena             Print arena(s) information
ptparam             Print malloc parameter(s) information
ptlist              Print a flat listing of all the chunks in an arena
ptchunk             Show one or more chunks metadata and contents
ptbin               Print unsorted/small/large bins information
ptfast              Print fast bins information
pttcache            Print tcache bins information
ptfree              Print all bins information
ptstats             Print memory alloc statistics similar to malloc_stats(3)
Note: Use a command name with -h to get additional help
```

## Commands' usage

Each command has detailed usage that you can print using `-h`:

```
(gdb) ptfree -h
usage:  [-c COUNT] [-v] [-h] [-x] [-X HEXDUMP_UNIT] [-m MAXBYTES] [-p PRINT_OFFSET] [-M METADATA]
        [-H HIGHLIGHT_ADDRESSES] [-G HIGHLIGHT_METADATA] [--highlight-only] [--json JSON_FILENAME]
        [--json-append] [-s SEARCH_VALUE] [-S SEARCH_TYPE] [--match-only] [--skip-header]
        [--depth SEARCH_DEPTH] [--cmds COMMANDS] [-o]

Print all bins information

Browse fast bins, tcache bins, unsorted/small/large bins.
Effectively calls into 'ptfast', 'pttcache' and 'ptbin' commands

optional arguments:
  -c COUNT, --count COUNT
                        Maximum number of chunks to print in each bin

generic optional arguments:
  -v, --verbose         Use verbose output (multiple for more verbosity)
  -h, --help            Show this help
  -x, --hexdump         Hexdump the chunk contents
  -X HEXDUMP_UNIT       Specify hexdump unit (1, 2, 4, 8 or dps) when using -x (default: 1)
  -m MAXBYTES, --maxbytes MAXBYTES
                        Max bytes to dump with -x
  -p PRINT_OFFSET       Print data inside at given offset (summary representation)
  -M METADATA, --metadata METADATA
                        Comma separated list of metadata to print (previously stored with the 'ptmeta' command)
  -H HIGHLIGHT_ADDRESSES, --highlight-addresses HIGHLIGHT_ADDRESSES
                        Comma separated list of addresses for chunks we want to highlight in the output
  -G HIGHLIGHT_METADATA, --highlight-metadata HIGHLIGHT_METADATA
                        Comma separated list of metadata (previously stored with the 'ptmeta' command) 
                        for chunks we want to highlight in the output
  --highlight-only      Only show the highlighted chunks (instead of just '*' them)
  --json JSON_FILENAME  Specify the json filename to save the output (Useful to diff 2 outputs)
  --json-append         Append to the filename instead of overwriting
  -s SEARCH_VALUE, --search SEARCH_VALUE
                        Search a value and show match/no match
  -S SEARCH_TYPE, --search-type SEARCH_TYPE
                        Specify search type (string, byte, word, dword or qword) when using -s (default: string)
  --match-only          Only show the matched chunks (instead of just show match/no match)
  --skip-header         Don't include chunk header contents in search results
  --depth SEARCH_DEPTH  How far into each chunk to search, starting from chunk header address
  --cmds COMMANDS       Semi-colon separated list of debugger commands to be executed for each chunk that is displayed 
                        ('@' is replaced by the chunk address)
  -o, --address-offset  Print offsets from the first printed chunk instead of addresses
```

# Common usage and example

## ptconfig

The first thing to make sure when using libptmalloc is to have the 
right glibc version configured in `libptmalloc`.

Note we could automatically detect the ptmalloc version (hence glibc) by pattern
matching on the ptmalloc structures but it is not implemented in libptmalloc yet.

The configured glibc version can be defined in the `libptmalloc.cfg` file:

```
[Glibc]
version = 2.27
tcache = true

```

It will then reflect using the `ptconfig` command:

```
(gdb) ptconfig
glibc version       2.27
tcache              enabled
```

You can also change it:

```
(gdb) ptconfig -v 2.27
```

## ptarena

We list all the arenas:

```
(gdb) ptarena -l
Retrieving 'main_arena'
Caching global 'main_arena' @ 0x7ffff7baec40
Arena(s) found:
  arena @ 0x7ffff7baec40
  arena @ 0x7ffff0000020
```

We show the arena fields:

```
(gdb) ptarena
Retrieving arena again
struct malloc_state @ 0x7ffff7baec40 {
mutex            = 0x0
flags            = 0x0
have_fastchunks  = 0x1
fastbinsY        = {...}
top              = 0x5555557b0a10
last_remainder   = 0x555555763de0
bins             = {...}
binmap           = {...}
next             = 0x7ffff0000020
next_free        = 0x0
attached_threads = 0x1
system_mem       = 0x63000
max_system_mem   = 0x63000
```

We show more fields:

```
(gdb) ptarena -v
Retrieving arena again
struct malloc_state @ 0x7ffff7baec40 {
mutex            = 0x0
flags            = 0x0
have_fastchunks  = 0x1
fastbinsY[0]     = 0x555555788ce0 (sz 0x20) [3 entries]
fastbinsY[1]     = 0x5555557ae3a0 (sz 0x30) [2 entries]
fastbinsY[2]     = 0x555555764eb0 (sz 0x40) [4 entries]
fastbinsY[3]     = 0x5555557693b0 (sz 0x50) [1 entry]
fastbinsY[5]     = 0x5555557a8660 (sz 0x70) [5 entries]
fastbinsY[6]     = 0x5555557887d0 (sz 0x80) [2 entries]
top              = 0x5555557b0a10
last_remainder   = 0x555555763de0
bins[0]          = 0x555555763d40, 0x5555557adf60 (unsorted) [5 entries]
bins[3]          = 0x5555557ae600, 0x5555557ae600 (small sz 0x40) [1 entry]
bins[8]          = 0x5555557a5cd0, 0x5555557801b0 (small sz 0x90) [5 entries]
bins[84]         = 0x55555577f530, 0x55555577f530 (large sz 0x970) [1 entry]
bins[96]         = 0x55555577e560, 0x55555577e560 (large sz 0xdf0) [1 entry]
bins[97]         = 0x555555789110, 0x555555789110 (large sz 0xff0) [1 entry]
bins[98]         = 0x55555576e160, 0x55555576e160 (large sz 0x11f0) [1 entry]
bins[101]        = 0x55555575a0d0, 0x5555557af390 (large sz 0x17f0) [3 entries]
bins[103]        = 0x555555796400, 0x5555557a1b10 (large sz 0x1bf0) [2 entries]
bins[104]        = 0x5555557a3ec0, 0x5555557802a0 (large sz 0x1df0) [3 entries]
bins[105]        = 0x55555578c780, 0x5555557ab210 (large sz 0x1ff0) [5 entries]
bins[106]        = 0x5555557a9180, 0x5555557a9180 (large sz 0x21f0) [1 entry]
bins[107]        = 0x5555557a6100, 0x5555557a6100 (large sz 0x23f0) [1 entry]
bins[112]        = 0x555555791810, 0x555555791810 (large sz 0x3ff0) [1 entry]
binmap[0]        = 0x35c
binmap[1]        = 0x0
binmap[2]        = 0x201000
binmap[3]        = 0x21f4e
next             = 0x7ffff0000020
next_free        = 0x0
attached_threads = 0x1
system_mem       = 0x63000
max_system_mem   = 0x63000
```

We show the 2nd arena by specifying its address:

```
(gdb) ptarena 0x7ffff0000020 -v
Caching arena @ 0x7ffff0000020
struct malloc_state @ 0x7ffff0000020 {
mutex            = 0x0
flags            = 0x2
have_fastchunks  = 0x0
top              = 0x7ffff0001600
last_remainder   = 0x0
bins[0]          = 0x7ffff00008c0, 0x7ffff00008c0 (unsorted) [1 entry]
binmap[0]        = 0x0
binmap[1]        = 0x0
binmap[2]        = 0x0
binmap[3]        = 0x0
next             = 0x7ffff7baec40
next_free        = 0x0
attached_threads = 0x0
system_mem       = 0x21000
max_system_mem   = 0x21000
```

## ptlist

We list all the chunks linearly in an arena. 
By default it prints one line per chunk:

```
(gdb) ptlist 0x7ffff0000020
Using manual arena calculation for heap start
flat heap listing for arena @ 0x7ffff0000020
0x7ffff00008c0 F sz:0x00250 fl:--P
0x7ffff0000b10 M sz:0x00410 fl:-N-
0x7ffff0000f20 M sz:0x00030 fl:-NP
0x7ffff0000f50 M sz:0x004b0 fl:-NP
0x7ffff0001400 M sz:0x00030 fl:-NP
0x7ffff0001430 M sz:0x00040 fl:-NP
0x7ffff0001470 M sz:0x00190 fl:-NP
0x7ffff0001600 F sz:0x1fa00 fl:--P (top)
0x7ffff0021000
Total of 8 chunks
```

Note: The `ptlist` commands support a lot of features from
the `ptchunk` command.

## ptchunk

### Allocated chunk

We print one allocated chunk:

```
(gdb) ptchunk 0x5555557998e0
0x5555557998e0 M sz:0x00060 fl:--P
```

We print the same allocated chunk with its header and data:

```
(gdb) ptchunk 0x5555557998e0 -v -x
struct malloc_chunk @ 0x5555557998e0 {
prev_size   = 0x0
size        = 0x60 (PREV_INUSE|)
0x50 bytes of chunk data:
0x5555557998f0:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  XXXXXXXXXXXXXXXX
0x555555799900:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  XXXXXXXXXXXXXXXX
0x555555799910:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  XXXXXXXXXXXXXXXX
0x555555799920:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  XXXXXXXXXXXXXXXX
0x555555799930:  58 58 58 58 58 58 58 58  58 00 00 00 00 00 00 00  XXXXXXXXX.......
```

### Free chunk in regular bin

We print one free chunk:

```
(gdb) ptchunk 0x555555799ab0
0x555555799ab0 F sz:0x00090 fl:--P
```

We print the same free chunk with its header and data:

```
(gdb) ptchunk 0x555555799ab0 -v -x
struct malloc_chunk @ 0x555555799ab0 {
prev_size   = 0x0
size        = 0x90 (PREV_INUSE|)
fd          = 0x5555557801b0
bk          = 0x555555784b30
0x70 bytes of chunk data:
0x555555799ad0:  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
0x555555799ae0:  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
0x555555799af0:  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
0x555555799b00:  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
0x555555799b10:  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
0x555555799b20:  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
0x555555799b30:  42 42 42 42 42 42 42 42  42 42 00 00 00 00 00 00  BBBBBBBBBB......
```

### Printing multiple chunks

We print multiple chunks. You can limit the number of chunks being printed:

```
(gdb) ptchunk 0x5555557998e0 -c 5
0x5555557998e0 M sz:0x00060 fl:--P
0x555555799940 M sz:0x000a0 fl:--P
0x5555557999e0 t sz:0x00080 fl:--P
0x555555799a60 M sz:0x00050 fl:--P
0x555555799ab0 F sz:0x00090 fl:--P
```

We differentiate chunks that are allocated `M`, freed in an 
unsorted/small/large bin `F`, freed in the fast bin `f` or freed in the tcache bin `t`.

### Combining options

By combininig all options:

```
(gdb) ptchunk 0x5555557998e0 -c 3 -v -x
struct malloc_chunk @ 0x5555557998e0 {
prev_size   = 0x0
size        = 0x60 (PREV_INUSE|)
0x50 bytes of chunk data:
0x5555557998f0:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  XXXXXXXXXXXXXXXX
0x555555799900:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  XXXXXXXXXXXXXXXX
0x555555799910:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  XXXXXXXXXXXXXXXX
0x555555799920:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  XXXXXXXXXXXXXXXX
0x555555799930:  58 58 58 58 58 58 58 58  58 00 00 00 00 00 00 00  XXXXXXXXX.......
--
struct malloc_chunk @ 0x555555799940 {
prev_size   = 0x0
size        = 0xa0 (PREV_INUSE|)
0x90 bytes of chunk data:
0x555555799950:  59 59 59 59 59 59 59 59  59 59 59 59 59 59 59 59  YYYYYYYYYYYYYYYY
0x555555799960:  59 59 59 59 59 59 59 59  59 59 59 59 59 59 59 59  YYYYYYYYYYYYYYYY
0x555555799970:  59 59 59 59 59 59 59 59  59 59 59 59 59 59 59 59  YYYYYYYYYYYYYYYY
0x555555799980:  59 59 59 59 59 59 59 59  59 59 59 59 59 59 59 59  YYYYYYYYYYYYYYYY
0x555555799990:  59 59 59 59 59 59 59 59  59 59 59 59 59 59 59 59  YYYYYYYYYYYYYYYY
0x5555557999a0:  59 59 59 59 59 59 59 59  59 59 59 59 59 59 59 59  YYYYYYYYYYYYYYYY
0x5555557999b0:  59 59 59 59 59 59 59 59  59 59 59 59 59 59 59 59  YYYYYYYYYYYYYYYY
0x5555557999c0:  59 59 59 59 59 59 59 59  59 59 59 59 59 59 59 59  YYYYYYYYYYYYYYYY
0x5555557999d0:  59 59 59 59 59 59 59 59  59 59 59 59 59 59 59 59  YYYYYYYYYYYYYYYY
--
struct malloc_chunk @ 0x5555557999e0 {
prev_size   = 0x0
size        = 0x80 (PREV_INUSE|)
struct tcache_entry @ 0x5555557999f0 {
next        = 0x555555788700
key         = 0x555555758010
0x60 bytes of chunk data:
0x555555799a00:  49 49 49 49 49 49 49 49  49 49 49 49 49 49 49 49  IIIIIIIIIIIIIIII
0x555555799a10:  49 49 49 49 49 49 49 49  49 49 49 49 49 49 49 49  IIIIIIIIIIIIIIII
0x555555799a20:  49 49 49 49 49 49 49 49  49 49 49 49 49 49 49 49  IIIIIIIIIIIIIIII
0x555555799a30:  49 49 49 49 49 49 49 49  49 49 49 49 49 49 49 49  IIIIIIIIIIIIIIII
0x555555799a40:  49 49 49 49 49 49 49 49  49 49 49 49 49 49 49 49  IIIIIIIIIIIIIIII
0x555555799a50:  49 49 49 49 49 49 49 49  49 49 49 49 49 49 49 49  IIIIIIIIIIIIIIII
```

## ptbin

We print all the unsorted/small/large bins. By default it won't print 
the empty bins:

```
(gdb) ptbin
Unsorted/small/large bins in malloc_state @ 0x7ffff7baec40
bins[0]          = 0x555555763d40, 0x5555557adf60 (unsorted) [5 entries]
bins[3]          = 0x5555557ae600, 0x5555557ae600 (small sz 0x40) [1 entry]
bins[8]          = 0x5555557a5cd0, 0x5555557801b0 (small sz 0x90) [5 entries]
bins[84]         = 0x55555577f530, 0x55555577f530 (large sz 0x970) [1 entry]
bins[96]         = 0x55555577e560, 0x55555577e560 (large sz 0xdf0) [1 entry]
bins[97]         = 0x555555789110, 0x555555789110 (large sz 0xff0) [1 entry]
bins[98]         = 0x55555576e160, 0x55555576e160 (large sz 0x11f0) [1 entry]
bins[101]        = 0x55555575a0d0, 0x5555557af390 (large sz 0x17f0) [3 entries]
bins[103]        = 0x555555796400, 0x5555557a1b10 (large sz 0x1bf0) [2 entries]
bins[104]        = 0x5555557a3ec0, 0x5555557802a0 (large sz 0x1df0) [3 entries]
bins[105]        = 0x55555578c780, 0x5555557ab210 (large sz 0x1ff0) [5 entries]
bins[106]        = 0x5555557a9180, 0x5555557a9180 (large sz 0x21f0) [1 entry]
bins[107]        = 0x5555557a6100, 0x5555557a6100 (large sz 0x23f0) [1 entry]
bins[112]        = 0x555555791810, 0x555555791810 (large sz 0x3ff0) [1 entry]
```

We print all the bins:

```
(gdb) ptbin -v
Unsorted/small/large bins in malloc_state @ 0x7ffff7baec40
bins[0]          = 0x555555763d40, 0x5555557adf60 (unsorted) [5 entries]
bins[1]          = 0x7ffff7baecb0, 0x7ffff7baecb0 (small sz 0x20) [EMPTY]
bins[2]          = 0x7ffff7baecc0, 0x7ffff7baecc0 (small sz 0x30) [EMPTY]
bins[3]          = 0x5555557ae600, 0x5555557ae600 (small sz 0x40) [1 entry]
bins[4]          = 0x7ffff7baece0, 0x7ffff7baece0 (small sz 0x50) [EMPTY]
bins[5]          = 0x7ffff7baecf0, 0x7ffff7baecf0 (small sz 0x60) [EMPTY]
bins[6]          = 0x7ffff7baed00, 0x7ffff7baed00 (small sz 0x70) [EMPTY]
bins[7]          = 0x7ffff7baed10, 0x7ffff7baed10 (small sz 0x80) [EMPTY]
bins[8]          = 0x5555557a5cd0, 0x5555557801b0 (small sz 0x90) [5 entries]
bins[9]          = 0x7ffff7baed30, 0x7ffff7baed30 (small sz 0xa0) [EMPTY]
...
```

We print all the chunks in a particular bin:

```
(gdb) ptbin -i 8
small bin 8 (sz 0x90)
0x5555557a5cd0 F sz:0x00090 fl:--P
0x555555783240 F sz:0x00090 fl:--P
0x555555784b30 F sz:0x00090 fl:--P
0x555555799ab0 F sz:0x00090 fl:--P
0x5555557801b0 F sz:0x00090 fl:--P
small bin 8: total of 5 chunks
```

## ptfast

We print all the fast bins. By default it won't print 
the empty bins:

```
(gdb) ptfast
Fast bins in malloc_state @ 0x7ffff7baec40
fastbinsY[0]     = 0x555555788ce0 (sz 0x20) [3 entries]
fastbinsY[1]     = 0x5555557ae3a0 (sz 0x30) [2 entries]
fastbinsY[2]     = 0x555555764eb0 (sz 0x40) [4 entries]
fastbinsY[3]     = 0x5555557693b0 (sz 0x50) [1 entry]
fastbinsY[5]     = 0x5555557a8660 (sz 0x70) [5 entries]
fastbinsY[6]     = 0x5555557887d0 (sz 0x80) [2 entries]
```

We print all the chunks in a particular bin. Note how we limit the number of chunks shown:

```
(gdb) ptfast -i 5 -c 3
fast bin 5 (sz 0x70)
0x5555557a8660 f sz:0x00070 fl:--P
0x555555763810 f sz:0x00070 fl:--P
0x5555557ae4b0 f sz:0x00070 fl:--P
fast bin 5: total of 3+ chunks
```

## pttcache

We print all the tcache bins. By default it won't print 
the empty bins:

```
(gdb) pttcache
struct tcache_perthread_struct @ 0x555555758010 {
entries[0]  = 0x5555557a3590 (sz 0x20) [7 entries]
entries[1]  = 0x5555557ae550 (sz 0x30) [7 entries]
entries[2]  = 0x5555557ae0c0 (sz 0x40) [7 entries]
entries[3]  = 0x55555576b480 (sz 0x50) [7 entries]
entries[4]  = 0x555555777430 (sz 0x60) [3 entries]
entries[5]  = 0x55555578ee90 (sz 0x70) [7 entries]
entries[6]  = 0x5555557a9040 (sz 0x80) [7 entries]
entries[7]  = 0x555555765040 (sz 0x90) [6 entries]
entries[8]  = 0x5555557ae420 (sz 0xa0) [7 entries]
entries[9]  = 0x55555575e3e0 (sz 0xb0) [4 entries]
entries[12] = 0x55555575d640 (sz 0xe0) [2 entries]
entries[14] = 0x5555557584d0 (sz 0x100) [1 entry]
...
```

We print all the chunks in a particular bin:

```
(gdb) pttcache -i 7
tcache bin 7 (sz 0x90)
0x555555765030 t sz:0x00090 fl:--P
0x55555579eaa0 t sz:0x00090 fl:---
0x5555557760a0 t sz:0x00090 fl:--P
0x5555557a5c40 t sz:0x00090 fl:---
0x555555764db0 t sz:0x00090 fl:--P
0x5555557a0ed0 t sz:0x00090 fl:--P
tcache bin 7: total of 6 chunks
```

## ptfree

It prints all the bins by combining the output of `ptbin`, `ptfast` and 
`pttcache`. It is quite verbose so we won't include an example here.

## ptstats

We print memory statistics for all the arenas:

```
(gdb) ptstats
Malloc Stats

Arena 0 @ 0x7ffff7baec40:
system bytes     = 405504 (0x63000)
free bytes       = 211008 (0x33840)
in use bytes     = 194496 (0x2f7c0)
Arena 1 @ 0x7ffff0000020:
system bytes     = 135168 (0x21000)
free bytes       = 130128 (0x1fc50)
in use bytes     = 2800 (0xaf0)

Total (including mmap):
system bytes     = 540672 (0x84000)
free bytes       = 341136 (0x53490)
in use bytes     = 197296 (0x302b0)
max mmap regions = 0
max mmap bytes   = 0
```

## ptmeta

We first notice this chunk holds the libgcc path:

```
(gdb) ptchunk 0x7ffff0001400 -v -x
struct malloc_chunk @ 0x7ffff0001400 {
prev_size   = 0x0
size        = 0x30 (PREV_INUSE|NON_MAIN_ARENA|)
0x20 bytes of chunk data:
0x7ffff0001410:  2F 6C 69 62 2F 78 38 36  5F 36 34 2D 6C 69 6E 75  /lib/x86_64-linu
0x7ffff0001420:  78 2D 67 6E 75 00 6C 69  62 67 63 63 5F 73 2E 73  x-gnu.libgcc_s.s
```

The 'ptmeta command is more advanced and allows to associate user-defined metadata
for given chunks' addresses. E.g. you can add a tag as metadata:

```
(gdb) ptmeta add 0x7ffff0001400 tag "libgcc path"
```

Then it can be show within other commands:

```
(gdb) ptchunk 0x7ffff0001400 -M tag
0x7ffff0001400 M sz:0x00030 fl:-NP | libgcc path |
```

Note: You can also associate a backtrace as metadata, which allows to
write your own heap tracer tool

# Cache

In order to speed up the execution of commands, libptmalloc caches
the ptmalloc structures as well as the addresses of the chunks in specific bins
when you execute certain commands.

```
(gdb) ptfast 0x7ffff7baec40
Fast bins in malloc_state @ 0x7ffff7baec40
fastbinsY[0]     = 0x555555788ce0 (sz 0x20) [3 entries]
fastbinsY[1]     = 0x5555557ae3a0 (sz 0x30) [2 entries]
fastbinsY[2]     = 0x555555764eb0 (sz 0x40) [4 entries]
fastbinsY[3]     = 0x5555557693b0 (sz 0x50) [1 entry]
fastbinsY[5]     = 0x5555557a8660 (sz 0x70) [5 entries]
fastbinsY[6]     = 0x5555557887d0 (sz 0x80) [2 entries]
```

That being said, by default, it won't use the cache, to avoid any misleading info:

```
(gdb) ptfast
Fast bins in malloc_state @ 0x7ffff7baec40
fastbinsY[0]     = 0x555555788ce0 (sz 0x20) [3 entries]
fastbinsY[1]     = 0x5555557ae3a0 (sz 0x30) [2 entries]
fastbinsY[2]     = 0x555555764eb0 (sz 0x40) [4 entries]
fastbinsY[3]     = 0x5555557693b0 (sz 0x50) [1 entry]
fastbinsY[5]     = 0x5555557a8660 (sz 0x70) [5 entries]
fastbinsY[6]     = 0x5555557887d0 (sz 0x80) [2 entries]
```

If you want to use the cache, when you know nothing has changed since the
last cached information, you can use the following:

```
(gdb) ptfast --use-cache
Fast bins in malloc_state @ 0x7ffff7baec40
fastbinsY[0]     = 0x555555788ce0 (sz 0x20) [3 entries]
fastbinsY[1]     = 0x5555557ae3a0 (sz 0x30) [2 entries]
fastbinsY[2]     = 0x555555764eb0 (sz 0x40) [4 entries]
fastbinsY[3]     = 0x5555557693b0 (sz 0x50) [1 entry]
fastbinsY[5]     = 0x5555557a8660 (sz 0x70) [5 entries]
fastbinsY[6]     = 0x5555557887d0 (sz 0x80) [2 entries]
```

# Advanced usage

## Searching chunks

By default, searching will show all chunks but show a match/no-match suffix.
Because we are limiting the number of chunks, and even the non-match, 
we see there is only one match:

```
(gdb) ptlist -s "GGGG" -c 9
flat heap listing for arena @ 0x7ffff7baec40
0x555555758000 M sz:0x00250 fl:--P [NO MATCH] (sbrk_base)
0x555555758250 M sz:0x00120 fl:--P [NO MATCH]
0x555555758370 M sz:0x00120 fl:--P [NO MATCH]
0x555555758490 M sz:0x00030 fl:--P [NO MATCH]
0x5555557584c0 t sz:0x00100 fl:--P [NO MATCH]
0x5555557585c0 M sz:0x000b0 fl:--P [NO MATCH]
0x555555758670 M sz:0x003c0 fl:--P [NO MATCH]
0x555555758a30 M sz:0x00310 fl:--P [NO MATCH]
0x555555758d40 M sz:0x00150 fl:--P [MATCH]
Total of 9+ chunks
```

If you only want to show matches, you use the following. Note how the 
no-matching chunks are not shown anymore:

```
(gdb) ptlist -s "GGGG" -c 2 --match-only
flat heap listing for arena @ 0x7ffff7baec40
0x555555758d40 M sz:0x00150 fl:--P [MATCH]
0x555555758e90 M sz:0x00050 fl:--P [MATCH]
Total of 2+ chunks
```

Analyzing the content, we see the value was found in the chunks header
in the second chunk:

```
(gdb) ptlist -s "GGGG" -c 2 --match-only -v -x
flat heap listing for arena @ 0x7ffff7baec40
struct malloc_chunk @ 0x555555758d40 {
prev_size   = 0x0
size        = 0x150 (PREV_INUSE|)
0x140 bytes of chunk data:
0x555555758d50:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758d60:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758d70:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758d80:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758d90:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758da0:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758db0:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758dc0:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758dd0:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758de0:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758df0:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e00:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e10:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e20:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e30:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e40:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e50:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e60:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e70:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e80:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
--
struct malloc_chunk @ 0x555555758e90 {
prev_size   = 0x474747474747
size        = 0x50 (PREV_INUSE|)
0x40 bytes of chunk data:
0x555555758ea0:  48 48 48 48 48 48 48 48  48 48 48 48 48 48 48 48  HHHHHHHHHHHHHHHH
0x555555758eb0:  48 48 48 48 48 48 48 48  48 48 48 48 48 48 48 48  HHHHHHHHHHHHHHHH
0x555555758ec0:  48 48 48 48 48 48 48 48  48 48 48 48 48 48 48 48  HHHHHHHHHHHHHHHH
0x555555758ed0:  48 48 48 48 48 48 48 48  48 48 48 48 48 48 48 48  HHHHHHHHHHHHHHHH
Total of 2+ chunks
```

To ignore the chunks headers, we use the following. We see a different
second chunk is shown:

```
(gdb) ptlist -s "GGGG" -c 2 --match-only -v -x --skip
flat heap listing for arena @ 0x7ffff7baec40
struct malloc_chunk @ 0x555555758d40 {
prev_size   = 0x0
size        = 0x150 (PREV_INUSE|)
0x140 bytes of chunk data:
0x555555758d50:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758d60:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758d70:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758d80:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758d90:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758da0:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758db0:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758dc0:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758dd0:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758de0:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758df0:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e00:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e10:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e20:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e30:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e40:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e50:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e60:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e70:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
0x555555758e80:  47 47 47 47 47 47 47 47  47 47 47 47 47 47 47 47  GGGGGGGGGGGGGGGG
--
struct malloc_chunk @ 0x555555760630 {
prev_size   = 0x0
size        = 0xb0 (PREV_INUSE|)
0xa0 bytes of chunk data:
0x555555760640:  4C 4C 4C 4C 4C 4C 4C 4C  4C 4C 4C 4C 4C 4C 4C 4C  LLLLLLLLLLLLLLLL
0x555555760650:  4C 4C 4C 4C 4C 4C 4C 4C  4C 4C 4C 4C 4C 4C 4C 4C  LLLLLLLLLLLLLLLL
0x555555760660:  4C 4C 4C 4C 4C 4C 4C 4C  4C 4C 4C 4C 4C 4C 4C 4C  LLLLLLLLLLLLLLLL
0x555555760670:  4C 4C 4C 4C 4C 4C 4C 4C  4C 4C 4C 4C 4C 4C 4C 4C  LLLLLLLLLLLLLLLL
0x555555760680:  4C 4C 4C 4C 4C 4C 4C 4C  4C 4C 4C 4C 4C 4C 4C 4C  LLLLLLLLLLLLLLLL
0x555555760690:  4C 4C 4C 4C 4C 4C 4C 4C  4C 4C 4C 4C 4C 4C 4C 4C  LLLLLLLLLLLLLLLL
0x5555557606a0:  4C 4C 4C 4C 4C 4C 4C 4C  4C 4C 4C 4C 4C 4C 4C 4C  LLLLLLLLLLLLLLLL
0x5555557606b0:  4C 4C 4C 4C 4C 4C 4C 4C  4C 4C 4C 4C 4C 4C 4C 4C  LLLLLLLLLLLLLLLL
0x5555557606c0:  4C 4C 4C 4C 4C 4C 4C 4C  4C 4C 4C 4C 4C 4C 4C 4C  LLLLLLLLLLLLLLLL
0x5555557606d0:  4C 4C 4C 4C 4C 4C 4C 4C  4C 4C 4C 4C 47 47 47 47  LLLLLLLLLLLLGGGG
Total of 2+ chunks
```

## Printing chunks of specific type(s)

We print chunks linearly, limiting to 10 chunks, and highlighting tcache free chunks
and regular bin free chunks:

```
(gdb) ptlist -c 10 -I "t,F"
flat heap listing for arena @ 0x7ffff7baec40
0x555555758000 M sz:0x00250 fl:--P (sbrk_base)
0x555555758250 M sz:0x00120 fl:--P
0x555555758370 M sz:0x00120 fl:--P
0x555555758490 M sz:0x00030 fl:--P
* 0x5555557584c0 t sz:0x00100 fl:--P
0x5555557585c0 M sz:0x000b0 fl:--P
0x555555758670 M sz:0x003c0 fl:--P
0x555555758a30 M sz:0x00310 fl:--P
0x555555758d40 M sz:0x00150 fl:--P
0x555555758e90 M sz:0x00050 fl:--P
Total of 10+ chunks
```

We filter to only show the highlighted chunks, resulting in skipping other types of chunks:

```
(gdb) ptlist -c 10 -I "t,F" --highlight-only
flat heap listing for arena @ 0x7ffff7baec40
* 0x5555557584c0 t sz:0x00100 fl:--P
* 0x555555759950 t sz:0x003a0 fl:--P
* 0x555555759e60 t sz:0x00270 fl:--P
* 0x55555575a0d0 F sz:0x017b0 fl:--P
* 0x55555575ba90 t sz:0x00080 fl:--P
* 0x55555575d480 t sz:0x000b0 fl:--P
* 0x55555575d5b0 t sz:0x00080 fl:--P
* 0x55555575d630 t sz:0x000e0 fl:--P
* 0x55555575e3d0 t sz:0x000b0 fl:--P
* 0x55555575e480 F sz:0x01ec0 fl:--P
Total of 10+ chunks
```

# Detailed commands' usage

We list all the commands' complete usage as a reference.

## ptconfig usage

```
(gdb) ptconfig -h
usage: [-h] [-v VERSION] [-t TCACHE] [-o DISTRIBUTION] [-r RELEASE]

Show/change ptmalloc configuration

optional arguments:
  -h, --help            Show this help
  -v VERSION, --version VERSION
                        Change the glibc version manually (e.g. 2.27)
  -t TCACHE, --tcache TCACHE
                        Enable or disable tcache (on/off)
  -o DISTRIBUTION, --distribution DISTRIBUTION
                        Target OS distribution (e.g. debian, ubuntu, centos, photon)
  -r RELEASE, --release RELEASE
                        Target OS release version (e.g. 10 for debian, 18.04 for ubuntu, 8 for centos, 3.0 for photon)

E.g.
  ptconfig
  ptconfig -v 2.27
  ptconfig -t off
```

## ptmeta usage

```
(gdb) ptmeta -h
usage: [-v] [-h] {add,del,list,config} ...

Handle metadata associated with chunk addresses

positional arguments:
  {add,del,list,config}
                        Action to perform
    add                 Save metadata for a given chunk address
    del                 Delete metadata associated with a given chunk address
    list                List metadata for a chunk address or all chunk addresses (debugging)
    config              Configure general metadata behaviour

optional arguments:
  -v, --verbose         Use verbose output (multiple for more verbosity)
  -h, --help            Show this help

NOTE: use 'ptmeta <action> -h' to get more usage info
```

```
(gdb) ptmeta add -h
usage:  add [-h] address key [value]

positional arguments:
  address     Address to link the metadata to
  key         Key name of the metadata (e.g. "backtrace", "color", "tag" or any name)
  value       Value of the metadata, associated with the key (required except when adding a "backtrace")

optional arguments:
  -h, --help  show this help message and exit

The saved metadata can then be shown in any other commands like 
'ptlist', 'ptchunk', 'pfree', etc.

E.g.
  ptmeta add mem-0x10 tag "service_user struct"
  ptmeta add 0xdead0030 color green
  ptmeta add 0xdead0030 backtrace
```

```
(gdb) ptmeta del -h
usage:  del [-h] address

positional arguments:
  address     Address to remove the metadata for

optional arguments:
  -h, --help  show this help message and exit

E.g.
  ptmeta del mem-0x10
  ptmeta del 0xdead0030
```

```
(gdb) ptmeta list -h
usage:  list [-h] [-M METADATA] [address]

positional arguments:
  address               Address to remove the metadata for

optional arguments:
  -h, --help            show this help message and exit
  -M METADATA, --metadata METADATA
                        Comma separated list of metadata to print

E.g.
  ptmeta list mem-0x10
  ptmeta list 0xdead0030 -M backtrace
  ptmeta list
  ptmeta list -vvvv
  ptmeta list -M "tag, backtrace:3
```

```
(gdb) ptmeta config -h
usage:  config [-h] feature key values [values ...]

positional arguments:
  feature     Feature to configure (e.g. "ignore")
  key         Key name of the metadata (e.g. "backtrace")
  values      Values of the metadata, associated with the key (e.g. list of function to ignore in a backtrace)

optional arguments:
  -h, --help  show this help message and exit

E.g.
  ptmeta config ignore backtrace _nl_make_l10nflist __GI___libc_free
```

## ptarena usage

```
(gdb) ptarena -h
usage: [-v] [-h] [-l] [--use-cache] [address]

Print arena(s) information

An arena is also known as an mstate.
Analyze the malloc_state structure's fields.

positional arguments:
  address        A malloc_mstate struct address. Optional with cached mstate

optional arguments:
  -v, --verbose  Use verbose output (multiple for more verbosity)
  -h, --help     Show this help
  -l             List the arenas addresses only
  --use-cache    Do not fetch mstate data if you know they haven't changed since last time they were cached

NOTE: Last defined mstate will be cached for future use
```

## ptparam usage

```
(gdb) ptparam -h
usage: [-h] [-l] [--use-cache] [address]

Print malloc parameter(s) information

Analyze the malloc_par structure's fields.

positional arguments:
  address      A malloc_par struct address. Optional with cached malloc parameters

optional arguments:
  -h, --help   Show this help
  -l           List malloc parameter(s)' address only
  --use-cache  Do not fetch parameters data if you know they haven't changed since last time they were cached

NOTE: Last defined mp_ will be cached for future use
```

## ptlist usage

```
(gdb) ptlist -h
usage:  [-C] [-c COUNT] [-v] [-h] [-x] [-X HEXDUMP_UNIT] [-m MAXBYTES] [-p PRINT_OFFSET]
        [-M METADATA] [-I HIGHLIGHT_TYPES] [-H HIGHLIGHT_ADDRESSES] [-G HIGHLIGHT_METADATA]
        [--highlight-only] [--use-cache] [--json JSON_FILENAME] [--json-append] [-s SEARCH_VALUE]
        [-S SEARCH_TYPE] [--match-only] [--skip-header] [--depth SEARCH_DEPTH] [--cmds COMMANDS]
        [-o]
        [address]

Print a flat listing of all the chunks in an arena

positional arguments:
  address               A malloc_mstate struct address. Optional with cached mstate

optional arguments:
  -C, --compact         Compact flat heap listing
  -c COUNT, --count COUNT
                        Number of chunks to print linearly

generic optional arguments:
  -v, --verbose         Use verbose output (multiple for more verbosity)
  -h, --help            Show this help
  -x, --hexdump         Hexdump the chunk contents
  -X HEXDUMP_UNIT       Specify hexdump unit (1, 2, 4, 8 or dps) when using -x (default: 1)
  -m MAXBYTES, --maxbytes MAXBYTES
                        Max bytes to dump with -x
  -p PRINT_OFFSET       Print data inside at given offset (summary representation)
  -M METADATA, --metadata METADATA
                        Comma separated list of metadata to print (previously stored with the 'ptmeta' command)
  -I HIGHLIGHT_TYPES, --highlight-types HIGHLIGHT_TYPES
                        Comma separated list of chunk types (M, F, f or t) for chunks we want to highlight in the output
  -H HIGHLIGHT_ADDRESSES, --highlight-addresses HIGHLIGHT_ADDRESSES
                        Comma separated list of addresses for chunks we want to highlight in the output
  -G HIGHLIGHT_METADATA, --highlight-metadata HIGHLIGHT_METADATA
                        Comma separated list of metadata (previously stored with the 'ptmeta' command) 
                        for chunks we want to highlight in the output
  --highlight-only      Only show the highlighted chunks (instead of just '*' them)
  --use-cache           Do not fetch any internal ptmalloc data if you know they haven't changed since
                        last time they were cached
  --json JSON_FILENAME  Specify the json filename to save the output (Useful to diff 2 outputs)
  --json-append         Append to the filename instead of overwriting
  -s SEARCH_VALUE, --search SEARCH_VALUE
                        Search a value and show match/no match
  -S SEARCH_TYPE, --search-type SEARCH_TYPE
                        Specify search type (string, byte, word, dword or qword) when using -s (default: string)
  --match-only          Only show the matched chunks (instead of just show match/no match)
  --skip-header         Don't include chunk header contents in search results
  --depth SEARCH_DEPTH  How far into each chunk to search, starting from chunk header address
  --cmds COMMANDS       Semi-colon separated list of debugger commands to be executed for each chunk that is displayed 
                        ('@' is replaced by the chunk address)
  -o, --address-offset  Print offsets from the first printed chunk instead of addresses

E.g.
ptlist -M "tag, backtrace:5" 
```

## ptchunk usage

```
(gdb) ptchunk -h
usage:  [-v] [-h] [-c COUNT] [-x] [-X HEXDUMP_UNIT] [-m MAXBYTES] [-n] [-p PRINT_OFFSET]
        [-M METADATA] [-I HIGHLIGHT_TYPES] [-H HIGHLIGHT_ADDRESSES] [-G HIGHLIGHT_METADATA]
        [--highlight-only] [--use-cache] [--json JSON_FILENAME] [--json-append] [-s SEARCH_VALUE]
        [-S SEARCH_TYPE] [--match-only] [--skip-header] [--depth SEARCH_DEPTH] [--cmds COMMANDS]
        [-o]
        [addresses [addresses ...]]

Show one or more chunks metadata and contents

Can provide you with a summary of a chunk (one-line) or more verbose information 
of every field (multiple lines). 
You can also list information of multiple chunks, search chunks, etc.

positional arguments:
  addresses             Address(es) to ptmalloc chunk headers

optional arguments:
  -v, --verbose         Use verbose output (multiple for more verbosity)
  -h, --help            Show this help
  -c COUNT, --count COUNT
                        Number of chunks to print linearly (also supports "unlimited"/0
                        or negative numbers to print chunks going backwards)
  -x, --hexdump         Hexdump the chunk contents
  -X HEXDUMP_UNIT       Specify hexdump unit (1, 2, 4, 8 or dps) when using -x (default: 1)
  -m MAXBYTES, --maxbytes MAXBYTES
                        Max bytes to dump with -x
  -n                    Do not output the trailing newline (summary representation)
  -p PRINT_OFFSET       Print data inside at given offset (summary representation)
  -M METADATA, --metadata METADATA
                        Comma separated list of metadata to print (previously stored with the 'ptmeta' command)
  -I HIGHLIGHT_TYPES, --highlight-types HIGHLIGHT_TYPES
                        Comma separated list of chunk types (M, F, f or t) for chunks we want to highlight in the output
  -H HIGHLIGHT_ADDRESSES, --highlight-addresses HIGHLIGHT_ADDRESSES
                        Comma separated list of addresses for chunks we want to highlight in the output
  -G HIGHLIGHT_METADATA, --highlight-metadata HIGHLIGHT_METADATA
                        Comma separated list of metadata (previously stored with the 'ptmeta' command) 
                        for chunks we want to highlight in the output
  --highlight-only      Only show the highlighted chunks (instead of just '*' them)
  --use-cache           Do not fetch any internal ptmalloc data if you know they haven't changed since
                        last time they were cached
  --json JSON_FILENAME  Specify the json filename to save the output (Useful to diff 2 outputs)
  --json-append         Append to the filename instead of overwriting
  -s SEARCH_VALUE, --search SEARCH_VALUE
                        Search a value and show match/no match
  -S SEARCH_TYPE, --search-type SEARCH_TYPE
                        Specify search type (string, byte, word, dword or qword) when using -s (default: string)
  --match-only          Only show the matched chunks (instead of just show match/no match)
  --skip-header         Don't include chunk header contents in search results
  --depth SEARCH_DEPTH  How far into each chunk to search, starting from chunk header address
  --cmds COMMANDS       Semi-colon separated list of debugger commands to be executed for each chunk that is displayed 
                        ('@' is replaced by the chunk address)
  -o, --address-offset  Print offsets from the first printed chunk instead of addresses

E.g.
ptchunk mem-0x10 -v -x -M "tag, backtrace"
ptchunk mem-0x10 -M "backtrace:5"

Allocated/free flag: M=allocated, F=freed, f=fast, t=tcache
Flag legend: P=PREV_INUSE, M=MMAPPED, N=NON_MAIN_ARENA
```

## ptbin usage

```
(gdb) ptbin -h
usage:  [-i INDEX] [-b SIZE] [-c COUNT] [-v] [-h] [-x] [-X HEXDUMP_UNIT] [-m MAXBYTES]
        [-p PRINT_OFFSET] [-M METADATA] [-H HIGHLIGHT_ADDRESSES] [-G HIGHLIGHT_METADATA]
        [--highlight-only] [--use-cache] [--json JSON_FILENAME] [--json-append] [-s SEARCH_VALUE]
        [-S SEARCH_TYPE] [--match-only] [--skip-header] [--depth SEARCH_DEPTH] [--cmds COMMANDS]
        [-o]

Print unsorted/small/large bins information

All these bins are implemented in the malloc_state.bins[] member. 
The unsorted bin is index 0, the small bins are indexes 1-62 and above 63 are large bins.

optional arguments:
  -i INDEX, --index INDEX
                        Index to the bin to show (0 to 126)
  -b SIZE, --bin-size SIZE
                        Small/large bin size to show
  -c COUNT, --count COUNT
                        Maximum number of chunks to print in each bin

generic optional arguments:
  -v, --verbose         Use verbose output (multiple for more verbosity)
  -h, --help            Show this help
  -x, --hexdump         Hexdump the chunk contents
  -X HEXDUMP_UNIT       Specify hexdump unit (1, 2, 4, 8 or dps) when using -x (default: 1)
  -m MAXBYTES, --maxbytes MAXBYTES
                        Max bytes to dump with -x
  -p PRINT_OFFSET       Print data inside at given offset (summary representation)
  -M METADATA, --metadata METADATA
                        Comma separated list of metadata to print (previously stored with the 'ptmeta' command)
  -H HIGHLIGHT_ADDRESSES, --highlight-addresses HIGHLIGHT_ADDRESSES
                        Comma separated list of addresses for chunks we want to highlight in the output
  -G HIGHLIGHT_METADATA, --highlight-metadata HIGHLIGHT_METADATA
                        Comma separated list of metadata (previously stored with the 'ptmeta' command) 
                        for chunks we want to highlight in the output
  --highlight-only      Only show the highlighted chunks (instead of just '*' them)
  --use-cache           Do not fetch any internal ptmalloc data if you know they haven't changed since
                        last time they were cached
  --json JSON_FILENAME  Specify the json filename to save the output (Useful to diff 2 outputs)
  --json-append         Append to the filename instead of overwriting
  -s SEARCH_VALUE, --search SEARCH_VALUE
                        Search a value and show match/no match
  -S SEARCH_TYPE, --search-type SEARCH_TYPE
                        Specify search type (string, byte, word, dword or qword) when using -s (default: string)
  --match-only          Only show the matched chunks (instead of just show match/no match)
  --skip-header         Don't include chunk header contents in search results
  --depth SEARCH_DEPTH  How far into each chunk to search, starting from chunk header address
  --cmds COMMANDS       Semi-colon separated list of debugger commands to be executed for each chunk that is displayed 
                        ('@' is replaced by the chunk address)
  -o, --address-offset  Print offsets from the first printed chunk instead of addresses
```

## ptfast usage

```
(gdb) ptfast -h
usage:  [-i INDEX] [-b SIZE] [-c COUNT] [-v] [-h] [-x] [-X HEXDUMP_UNIT] [-m MAXBYTES]
        [-p PRINT_OFFSET] [-M METADATA] [-H HIGHLIGHT_ADDRESSES] [-G HIGHLIGHT_METADATA]
        [--highlight-only] [--use-cache] [--json JSON_FILENAME] [--json-append] [-s SEARCH_VALUE]
        [-S SEARCH_TYPE] [--match-only] [--skip-header] [--depth SEARCH_DEPTH] [--cmds COMMANDS]
        [-o]
        [address]

Print fast bins information

They are implemented in the malloc_state.fastbinsY[] member.

positional arguments:
  address               An optional arena address

optional arguments:
  -i INDEX, --index INDEX
                        Index to the fast bin to show (0 to 9)
  -b SIZE, --bin-size SIZE
                        Fast bin size to show
  -c COUNT, --count COUNT
                        Maximum number of chunks to print in each bin

generic optional arguments:
  -v, --verbose         Use verbose output (multiple for more verbosity)
  -h, --help            Show this help
  -x, --hexdump         Hexdump the chunk contents
  -X HEXDUMP_UNIT       Specify hexdump unit (1, 2, 4, 8 or dps) when using -x (default: 1)
  -m MAXBYTES, --maxbytes MAXBYTES
                        Max bytes to dump with -x
  -p PRINT_OFFSET       Print data inside at given offset (summary representation)
  -M METADATA, --metadata METADATA
                        Comma separated list of metadata to print (previously stored with the 'ptmeta' command)
  -H HIGHLIGHT_ADDRESSES, --highlight-addresses HIGHLIGHT_ADDRESSES
                        Comma separated list of addresses for chunks we want to highlight in the output
  -G HIGHLIGHT_METADATA, --highlight-metadata HIGHLIGHT_METADATA
                        Comma separated list of metadata (previously stored with the 'ptmeta' command) 
                        for chunks we want to highlight in the output
  --highlight-only      Only show the highlighted chunks (instead of just '*' them)
  --use-cache           Do not fetch any internal ptmalloc data if you know they haven't changed since
                        last time they were cached
  --json JSON_FILENAME  Specify the json filename to save the output (Useful to diff 2 outputs)
  --json-append         Append to the filename instead of overwriting
  -s SEARCH_VALUE, --search SEARCH_VALUE
                        Search a value and show match/no match
  -S SEARCH_TYPE, --search-type SEARCH_TYPE
                        Specify search type (string, byte, word, dword or qword) when using -s (default: string)
  --match-only          Only show the matched chunks (instead of just show match/no match)
  --skip-header         Don't include chunk header contents in search results
  --depth SEARCH_DEPTH  How far into each chunk to search, starting from chunk header address
  --cmds COMMANDS       Semi-colon separated list of debugger commands to be executed for each chunk that is displayed 
                        ('@' is replaced by the chunk address)
  -o, --address-offset  Print offsets from the first printed chunk instead of addresses
```

## pttcache usage

```
(gdb) pttcache -h
usage:  [-l] [-i INDEX] [-b SIZE] [-c COUNT] [-v] [-h] [-x] [-X HEXDUMP_UNIT] [-m MAXBYTES]
        [-p PRINT_OFFSET] [-M METADATA] [-H HIGHLIGHT_ADDRESSES] [-G HIGHLIGHT_METADATA]
        [--highlight-only] [--use-cache] [--json JSON_FILENAME] [--json-append] [-s SEARCH_VALUE]
        [-S SEARCH_TYPE] [--match-only] [--skip-header] [--depth SEARCH_DEPTH] [--cmds COMMANDS]
        [-o]
        [address]

Print tcache bins information

All these bins are part of the tcache_perthread_struct structure. 
tcache is only available from glibc 2.26

positional arguments:
  address               An optional tcache address

optional arguments:
  -l                    List tcache(s)' addresses only
  -i INDEX, --index INDEX
                        Index to the tcache bin to show (0 to 63)
  -b SIZE, --bin-size SIZE
                        Tcache bin size to show
  -c COUNT, --count COUNT
                        Maximum number of chunks to print in each bin

generic optional arguments:
  -v, --verbose         Use verbose output (multiple for more verbosity)
  -h, --help            Show this help
  -x, --hexdump         Hexdump the chunk contents
  -X HEXDUMP_UNIT       Specify hexdump unit (1, 2, 4, 8 or dps) when using -x (default: 1)
  -m MAXBYTES, --maxbytes MAXBYTES
                        Max bytes to dump with -x
  -p PRINT_OFFSET       Print data inside at given offset (summary representation)
  -M METADATA, --metadata METADATA
                        Comma separated list of metadata to print (previously stored with the 'ptmeta' command)
  -H HIGHLIGHT_ADDRESSES, --highlight-addresses HIGHLIGHT_ADDRESSES
                        Comma separated list of addresses for chunks we want to highlight in the output
  -G HIGHLIGHT_METADATA, --highlight-metadata HIGHLIGHT_METADATA
                        Comma separated list of metadata (previously stored with the 'ptmeta' command) 
                        for chunks we want to highlight in the output
  --highlight-only      Only show the highlighted chunks (instead of just '*' them)
  --use-cache           Do not fetch any internal ptmalloc data if you know they haven't changed since
                        last time they were cached
  --json JSON_FILENAME  Specify the json filename to save the output (Useful to diff 2 outputs)
  --json-append         Append to the filename instead of overwriting
  -s SEARCH_VALUE, --search SEARCH_VALUE
                        Search a value and show match/no match
  -S SEARCH_TYPE, --search-type SEARCH_TYPE
                        Specify search type (string, byte, word, dword or qword) when using -s (default: string)
  --match-only          Only show the matched chunks (instead of just show match/no match)
  --skip-header         Don't include chunk header contents in search results
  --depth SEARCH_DEPTH  How far into each chunk to search, starting from chunk header address
  --cmds COMMANDS       Semi-colon separated list of debugger commands to be executed for each chunk that is displayed 
                        ('@' is replaced by the chunk address)
  -o, --address-offset  Print offsets from the first printed chunk instead of addresses
```

## ptfree usage

```
(gdb) ptfree -h
usage:  [-c COUNT] [-v] [-h] [-x] [-X HEXDUMP_UNIT] [-m MAXBYTES] [-p PRINT_OFFSET] [-M METADATA]
        [-H HIGHLIGHT_ADDRESSES] [-G HIGHLIGHT_METADATA] [--highlight-only] [--json JSON_FILENAME]
        [--json-append] [-s SEARCH_VALUE] [-S SEARCH_TYPE] [--match-only] [--skip-header]
        [--depth SEARCH_DEPTH] [--cmds COMMANDS] [-o]

Print all bins information

Browse fast bins, tcache bins, unsorted/small/large bins.
Effectively calls into 'ptfast', 'pttcache' and 'ptbin' commands

optional arguments:
  -c COUNT, --count COUNT
                        Maximum number of chunks to print in each bin

generic optional arguments:
  -v, --verbose         Use verbose output (multiple for more verbosity)
  -h, --help            Show this help
  -x, --hexdump         Hexdump the chunk contents
  -X HEXDUMP_UNIT       Specify hexdump unit (1, 2, 4, 8 or dps) when using -x (default: 1)
  -m MAXBYTES, --maxbytes MAXBYTES
                        Max bytes to dump with -x
  -p PRINT_OFFSET       Print data inside at given offset (summary representation)
  -M METADATA, --metadata METADATA
                        Comma separated list of metadata to print (previously stored with the 'ptmeta' command)
  -H HIGHLIGHT_ADDRESSES, --highlight-addresses HIGHLIGHT_ADDRESSES
                        Comma separated list of addresses for chunks we want to highlight in the output
  -G HIGHLIGHT_METADATA, --highlight-metadata HIGHLIGHT_METADATA
                        Comma separated list of metadata (previously stored with the 'ptmeta' command) 
                        for chunks we want to highlight in the output
  --highlight-only      Only show the highlighted chunks (instead of just '*' them)
  --json JSON_FILENAME  Specify the json filename to save the output (Useful to diff 2 outputs)
  --json-append         Append to the filename instead of overwriting
  -s SEARCH_VALUE, --search SEARCH_VALUE
                        Search a value and show match/no match
  -S SEARCH_TYPE, --search-type SEARCH_TYPE
                        Specify search type (string, byte, word, dword or qword) when using -s (default: string)
  --match-only          Only show the matched chunks (instead of just show match/no match)
  --skip-header         Don't include chunk header contents in search results
  --depth SEARCH_DEPTH  How far into each chunk to search, starting from chunk header address
  --cmds COMMANDS       Semi-colon separated list of debugger commands to be executed for each chunk that is displayed 
                        ('@' is replaced by the chunk address)
  -o, --address-offset  Print offsets from the first printed chunk instead of addresses
```

## ptstats usage

```
(gdb) ptstats -h
usage: [-v] [-h]

Print memory alloc statistics similar to malloc_stats(3)

optional arguments:
  -v, --verbose  Use verbose output (multiple for more verbosity)
  -h, --help     Show this help
```

# Comparison with other tools

## libheap

libptmalloc is heavily based on other tools like 
[libheap](https://github.com/cloudburst/libheap) even though a lot has been
changed or added.

The following table shows differences:

| libheap          | libptmalloc      | Note |
|------------------|------------------|------|
| print_bin_layout | ptbin -i <index> | print_bin_layout only includes small bins. ptbin also includes unsorted and large bins |
| heapls | ptlist |      |
| heaplsc | ptlist --compact |      |
| mstats | ptstats |      |
| smallbins | ptbin | ptbin also includes unsorted and large bins |
| fastbins | ptfast |      |
| N/A | pttcache |      |
| freebin | ptfree | ptfree also includes tcache bins |

# Notes

This documentation is automatically generated by [doc.sh](../test/doc.sh). 
This also allows people to replicate the commands manually into a debugger


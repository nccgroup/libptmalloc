#!/usr/bin/python3
# Helper to generate functions in libptmalloc code to convert an index in a bin
# (tcache, fast, regular bin) into the corresponding chunk size (and vice versa)
# It can also parses the output of logs generated by test.sh to see what chunks
# get allocated in what bin, for that same purpose.

import re
import sys

logfile = "test64.log"
#logfile = "test32.log"
#logfile = "test_large64.log"
#logfile = "test_large32.log"

debug = False
def debug_print(s, end=None):
    if debug:
        print(s, end=end)

# init them so they are ordered when printing
tcache_bins = {}
for i in range(64):
    tcache_bins[i] = -1
fast_bins = {}
for i in range(10):
    fast_bins[i] = -1
bins = {}
for i in range(127):
    bins[i] = -1

def parse_logfile():
    """Parse a logfile generated by test.sh to build the bin dictionary above"""
    unset = True
    f = open(logfile, "r")
    for line in f:
        debug_print(f"line = '{line[:-1]}'")
        if line.startswith("---"):
            unset = True
        m = re.match("tcache bin ([0-9]+) \(.*", line)
        if m:
            if unset is False:
                print("error parsing")
                sys.exit(1)
            curr_bin = tcache_bins
            curr_index = int(m.group(1))
            unset = False
            continue
        m = re.match("fast bin ([0-9]+) \(.*", line)
        if m:
            if unset is False:
                print("error parsing")
                sys.exit(1)
            curr_bin = fast_bins
            curr_index = int(m.group(1))
            unset = False
            continue
        m = re.match("(large|small|unsorted|large uncategorized) bin ([0-9]+) \(.*", line)
        if m:
            if unset is False:
                print("error parsing")
                sys.exit(1)
            curr_bin = bins
            curr_index = int(m.group(2))
            unset = False
            continue
        m = re.match("[0-9a-fx]+ .* sz:([0-9a-fx]+) .*", line)
        if m:
            if unset is True:
                print("error parsing")
                sys.exit(1)
            size = int(m.group(1), 16)
            if curr_index not in curr_bin.keys():
                curr_bin[curr_index] = size
            elif size > curr_bin[curr_index]:
                curr_bin[curr_index] = size
    f.close()

def dump_all():
    """Dump all bins parsed with parse_logfile()"""
    print("tcache bins:")
    for k,v in tcache_bins.items():
        print(f"{k} -> {v:#x}")
    print("fast bins:")
    for k,v in fast_bins.items():
        print(f"{k} -> {v:#x}")
    print("regular bins:")
    for k,v in bins.items():
        print(f"{k} -> {v:#x}")

def generate_tcache_64():
    """Generate python code matching the maximum encountered size empirically parsed with parse_logfile"""
    print("    def tcache_bin_size_XX(self, idx):")
    for k,v in tcache_bins.items():
        generate_if_case(v, k)
    print("    def tcache_bin_index_XX(self, size):")
    for k,v in tcache_bins.items():
        generate_if_case(v, k)

# uncomment the one you don't want to use
def generate_if_case(size, idx):
    """Helper function to generate python code"""
    # for tcache/fast bins
    # print(f"        elif size == {size:#x}:")
    # print(f"            return {idx}")
    # for regular bins
    print(f"        elif size <= {size:#x}:")
    print(f"            return {idx}")
    # for tcache/fast/regular bins
    # print(f"        elif idx == {idx}:")
    # print(f"            return {size:#x}")

# See https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=6e766d11bc85b6480fa5c9f2a76559f8acf9deb5;hb=HEAD#l1388
def generate_bin_64():
    """Generate python code for small/large bin: chunk size <-> index (in both directions) for 64-bit"""
    print("    def small_bin_index_64(self, size):")
    size = 0x10
    for k in range(1, 63):
        size += 0x10
        generate_if_case(size, k)
    print("    def large_bin_index_64(self, size):")
    for k in range(63, 96):
        size += 0x40 # 64
        generate_if_case(size, k)
    for k in range(96, 97):
        size += 0x1c0
        generate_if_case(size, k)
    for k in range(97, 111):
        size += 0x200 # 512
        generate_if_case(size, k)
    for k in range(111, 112):
        size += 0x600
        generate_if_case(size, k)
    for k in range(112, 119):
        size += 0x1000 # 4096
        generate_if_case(size, k)
    for k in range(119, 120):
        size += 0x6000
        generate_if_case(size, k)
    for k in range(120, 123):
        size += 0x8000 # 32768
        generate_if_case(size, k)
    for k in range(123, 126):
        size += 0x40000 # 32768
        generate_if_case(size, k)

# See https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=6e766d11bc85b6480fa5c9f2a76559f8acf9deb5;hb=HEAD#l1388
def generate_bin_32():
    """Generate python code for small/large bin: chunk size <-> index (in both directions) for 32-bit"""
    print("    def small_bin_index_32(self, size):")
    size = 0x0
    for k in range(1, 63):
        size += 0x10
        generate_if_case(size, k)
    print("    def large_bin_index_32(self, size):")
    for k in range(63, 64):
        size += 0x10
        generate_if_case(size, k)
    for k in range(64, 96):
        size += 0x40 # 64
        generate_if_case(size, k)
    for k in range(96, 111):
        size += 0x200 # 512
        generate_if_case(size, k)
    for k in range(111, 112):
        size += 0x600
        generate_if_case(size, k)
    for k in range(112, 119):
        size += 0x1000 # 4096
        generate_if_case(size, k)
    for k in range(119, 120):
        size += 0x6000
        generate_if_case(size, k)
    for k in range(120, 123):
        size += 0x8000 # 32768
        generate_if_case(size, k)
    for k in range(123, 126):
        size += 0x40000 # 32768
        generate_if_case(size, k)

if False:
    parse_logfile()
    dump_all()
elif False:
    parse_logfile()
    generate_tcache_64()
elif False:
    generate_bin_32()
elif True:
    generate_bin_64()

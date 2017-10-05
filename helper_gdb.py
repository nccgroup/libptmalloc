#!/usr/bin/python3
#
# This file is part of libptmalloc.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>

import traceback, struct
import os, re, json, pickle, gdb, sys
from functools import wraps
import helper as h
import importlib
importlib.reload(h)

class logger:
    def logmsg(s, debug=True):
        if not debug:
            return
        if type(s) == str:
            print("[helper_gdb] " + s)
        else:
            print(s)

def get_info():
    res = gdb.execute("maintenance info sections ?", to_string=True)
    bin_name = os.path.basename(h.build_bin_name(res))
    if not bin_name:
        raise("get_info: failed to find bin name")
    return bin_name

def get_arch():
    res = gdb.execute("maintenance info sections ?", to_string=True)
    if "elf32-i386" in res and "elf64-x86-64" in res:
        raise("get_arch: could not determine arch (1)")
    if "elf32-i386" not in res and "elf64-x86-64" not in res:
        raise("get_arch: could not determine arch (2)")
    if "elf32-i386" in res:
        return "elf32-i386"
    elif "elf64-x86-64" in res:
        return "elf64-x86-64"
    else:
        raise("get_arch: failed to find arch")

def get_inferior():
    try:
        if len(gdb.inferiors()) == 0:
            print("No gdb inferior could be found.")
            return -1
        else:
            inferior = gdb.inferiors()[0]
            return inferior
    except AttributeError:
        print("This gdb's python support is too old.")
        exit()

def has_inferior(f):
    "decorator to make sure we have an inferior to operate on"

    @wraps(f)
    def with_inferior(*args, **kwargs):
        inferior = get_inferior()
        if inferior != -1 and inferior != None:
            if (inferior.pid != 0) and (inferior.pid is not None):
                return f(*args, **kwargs)
            else:
                print("No debugee could be found.  Attach or start a program.")
                exit()
        else:
            exit()
    return with_inferior

def retrieve_sizesz():
    "Retrieve the SIZE_SZ after binary loading finished, this allows import within .gdbinit"

    _machine = get_arch()

    if "elf64" in _machine:
        SIZE_SZ = 8
    elif "elf32" in _machine:
        SIZE_SZ = 4
    else:
        raise Exception("Retrieving the SIZE_SZ failed.")

    if SIZE_SZ == 4:
        pass
    elif SIZE_SZ == 8:
        pass
    
    return SIZE_SZ

def mutex_lock(ar_ptr, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    ar_ptr.mutex = 1
    try:
        inferior.write_memory(ar_ptr.address, struct.pack("<I", ar_ptr.mutex))
    except gdb.MemoryError:
        pass

def mutex_unlock(ar_ptr, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    ar_ptr.mutex = 0
    try:
        inferior.write_memory(ar_ptr.address, struct.pack("<I", ar_ptr.mutex))
    except gdb.MemoryError:
        pass
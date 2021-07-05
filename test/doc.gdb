
set verbose on
set disassembly-flavor intel
set height 0
set pagination off
set debug-file-directory /usr/lib/debug

# Disable ASLR so we have deterministic documentation
set disable-randomization

b main
commands
    silent
    source ../pyptmalloc-dev.py
    d 1
    c
end

run

# This will be executed when it hits the "int3" of our "build/test1" binary
source doc2.gdb
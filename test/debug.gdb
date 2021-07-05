
set verbose on
set disassembly-flavor intel
set height 0
set pagination off
set debug-file-directory /usr/lib/debug

# Dump gdb session to a file
# https://stackoverflow.com/questions/1707167/how-to-dump-the-entire-gdb-session-to-a-file-including-commands-i-type-and-thei
#set logging file gdb_session.log
#set logging on

b main
commands
    silent
    source ../pyptmalloc-dev.py
    # DEBUG: testing with old libheap
    #source ../../libheap/dev.py
    d 1
    c
end

run

# NOTE: we can't just do that from test.py as it won't be taken into account into gdb?

printf "Logging into a file\n"
# Dump gdb session to a file
# https://stackoverflow.com/questions/1707167/how-to-dump-the-entire-gdb-session-to-a-file-including-commands-i-type-and-thei
set logging file test.log
set logging overwrite off
set logging on

source test.py

set logging off
# NOTE: we can't just do that from doc.py as it won't be taken into account into gdb?

printf "Logging into a file\n"
# Dump gdb session to a file
# https://stackoverflow.com/questions/1707167/how-to-dump-the-entire-gdb-session-to-a-file-including-commands-i-type-and-thei
set logging file ../docs/UserGuide.md
set logging overwrite on
set logging on

source doc.py

set logging off
#!/bin/bash
# e.g. debug.sh build/test1 1337

gdb -q -x debug.gdb --args ${1} ${2}

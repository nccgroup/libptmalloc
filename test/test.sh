#!/bin/bash
# Allows to test different layouts
# NB: delete `test.log` before running it to erase previous results
# logging 100 items takes ~ 27-35 minutes

for i in {1..100}
do 
    echo ------------------------------------------- >> test.log
    echo Handling $i >> test.log
    gdb -q -x test.gdb --args build/test1 $i
    #gdb -q -x test.gdb --args build/test1-32 $i
    #gdb -q -x test.gdb --args build/test2 $i
    #gdb -q -x test.gdb --args build/test2-32 $i
done


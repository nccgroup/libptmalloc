#!/bin/bash
# Allows to generate docs/UserGuide.md

gdb -q -x doc.gdb --args build/testdoc 1
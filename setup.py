#!/usr/bin/env python
#
# This file is part of libptmalloc.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>

from distutils.core import setup

setup(name='libheap',
      version='0.1',
      description='gdb python library for examining the glibc heap (ptmalloc)',
      author='cloud',
      url='https://github.com/cloudburst/libheap',
      license="MIT",
      keywords="ptmalloc gdb python glibc",
      py_modules=['libheap', 'printutils', 'prettyprinters']
     )

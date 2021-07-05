# -*- coding: future_fstrings -*-
#!/usr/bin/env python

from distutils.core import setup

setup(
    name='libptmalloc',
    packages=['libptmalloc', 'libptmalloc.pydbg', 'libptmalloc.ptmalloc',
              'libptmalloc.frontend', 'libptmalloc.frontend.commands',
              'libptmalloc.frontend.commands.gdb'],
    package_data={'libptmalloc': ['libptmalloc.cfg']},
    version='1.0',
    description='python library for examining ptmalloc (glibc userland heap)',
    author='Aaron Adams and Cedric Halbronn (NCC Group)',
    url='https://github.com/nccgroup/libptmalloc',
    license='MIT',
    keywords='ptmalloc gdb python glibc',
)

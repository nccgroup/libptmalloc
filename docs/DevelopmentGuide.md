<!-- vim-markdown-toc GFM -->

* [Design](#design)
* [pyptmalloc-dev.py](#pyptmalloc-devpy)
* [dev branch](#dev-branch)
    * [Python namespaces limitation](#python-namespaces-limitation)
    * [Do not use `from XXX import YYY`](#do-not-use-from-xxx-import-yyy)
* [glibc references](#glibc-references)
    * [glibc recommended versions](#glibc-recommended-versions)

<!-- vim-markdown-toc -->


# Design

The following design abstracting the debugger was taken from [libheap](https://github.com/cloudburst/libheap):

```
-----------------------------------------------------------------------
                       debugger frontend (commands and prettyprinters)
                                                      libptmalloc/frontend

                     +-----+
                     |     |
                     | gdb |
                     |     |
                     +--+--+
                        |
------------------------+----------------------------------------------
                        |               core logic (debugger-agnostic)
                        |                             libptmalloc/ptmalloc
                   +----+-----+
                   |          |
                   | ptmalloc |
                   |          |
                   +----+-----+
                        |
------------------------+----------------------------------------------
                        |                      debugger-dependent APIs
                        |                                libptmalloc/pydbg
   +--------------+-----+---------+-------------+
   |              |               |             |
+--+---+   +------+------+   +----+----+   +----+---+
|      |   |             |   |         |   |        |
| lldb |   | pygdbpython |   | pygdbmi |   | r2pipe |
| TODO |   |             |   |  TODO   |   |  TODO  |
|      |   |             |   |         |   |        |
+---+--+   +-------+-----+   +---+-----+   +----+---+
    |              |             |              |
    |              |             |    +---------+
    |              |             |    |
----+--------------+-------------+----+--------------------------------
    |              |             |    |      debugger-provided backend
    |              |             | +--+
    |              |    +--------+ |
 +--+---+       +--+--+ |   +------+-+
 |      |       |     | |   |        |
 | lldb |       | gdb +-+   | ptrace |
 |      |       |     |     |        |
 +------+       +-----+     +--------+
-----------------------------------------------------------------------
```

# pyptmalloc-dev.py

The normal way to use libptmalloc is to install it in Python libraries with `setup.py` but during development it is easier to use `pyptmalloc-dev.py` that will import libptmalloc after adding the root folder in the Python path.

# dev branch

The `dev` branch only supports Python >= 3.7. This is for commodity reasons, as detailed below and in the following [post](https://stackoverflow.com/questions/62524794/python-submodule-importing-correctly-in-python-3-7-but-not-3-6).

## Python namespaces limitation

One quirk of Python namespaces and tools like gdb which allows importing Python files is that it won't reload files that have been already imported, except if you especially request it. So let's consider a scenario where you source `A.py` which imports `B.py` (using `import B` or `from B import *`), it will import `B`. Now you modify `B.py` and re-source `A.py` in your debugger to test your changes. Unfortunately the changes made to `B.py` won't be taken into account. The only solution will be to reload gdb entirely before reloading `A.py`.

To work around that limitation, we use `importlib.reload()` in the dev branch for all the imported modules. This slows down significantly reloading libptmalloc but it is still faster than reloading gdb :)

## Do not use `from XXX import YYY`

When modifying libptmalloc's source code, it is handy to be able to re-import libptmalloc in gdb without having to restart gdb itself.

In the `master` branch, we use: `from libptmalloc import *`.

In the `dev` branch, we don't. We need to use `importlib.reload()` for all imported sub modules, hence we never use `from XXX import YYY` but instead always use `import XXX` so we can then use `importlib.reload(XXX)`.

# glibc references

The main reference to use when modifying libptmalloc is the different versions of the glibc source code from [here](http://ftp.gnu.org/gnu/glibc/).
E.g. comparing glibc 2.25 and 2.26 shows the introduction of tcache (`USE_TCACHE`).

## glibc recommended versions

In particular we recommend having at least the following versions:

* https://ftp.gnu.org/gnu/glibc/glibc-2.22.tar.gz
* https://ftp.gnu.org/gnu/glibc/glibc-2.23.tar.gz (+ malloc_state.attached_threads)
* https://ftp.gnu.org/gnu/glibc/glibc-2.25.tar.gz
* https://ftp.gnu.org/gnu/glibc/glibc-2.26.tar.gz (+ USE_TCACHE)
* https://ftp.gnu.org/gnu/glibc/glibc-2.27.tar.gz (+ malloc_state.have_fastchunks)

There are important changes between 2 versions that follow each other above.
<!-- vim-markdown-toc GFM -->

* [Requirements](#requirements)
    * [Debugger/Python](#debuggerpython)
    * [Glibc debug symbols](#glibc-debug-symbols)
        * [Ubuntu](#ubuntu)
        * [Fedora](#fedora)
        * [CentOS](#centos)
        * [PhotonOS](#photonos)
* [libptmalloc installation](#libptmalloc-installation)
    * [General installation](#general-installation)
    * [Use without installation](#use-without-installation)

<!-- vim-markdown-toc -->

# Requirements

## Debugger/Python

libptmalloc currently works with any gdb version that supports Python >= 3.5.

libptmalloc code attempts to abstract the debugger so could theoretically be ported to any debugger with Python support.

## Glibc debug symbols

Although libptmalloc may not require a glibc compiled with gdb debugging support and symbols, it functions best if you do use one.  Without debug symbols you will need to supply the address of `main_arena`, `mp_` and optionally `tcache` yourself.

### Ubuntu

```
apt-get install libc6-dbg
```

### Fedora

```
yum install yum-utils
debuginfo-install glibc
```

or

```
dnf install dnf-plugins-core
dnf debuginfo-install glibc
```

### CentOS

```
yum install glibc-debuginfo
```

### PhotonOS

On PhotonOS 1.0, the normal `glibc` library already includes symbols. On PhotonOS 3.0, you can get them from:

```
tdnf install glibc-debuginfo
```

# libptmalloc installation

Clone the repo:

```
git clone https://github.com/nccgroup/libptmalloc
```

Install the Python packages. Note that [future-fstrings](https://pypi.org/project/future-fstrings/) is only required for Python < 3.7 (so effectively for Python 3.5 and 3.6):

```
pip3 install -r libptmalloc/requirements.txt
```

## General installation

Then install it globally:

```
sudo pip3 install ./libptmalloc/
```

or

```
cd libptmalloc
sudo python3 setup.py install
```

Then you can load it into gdb:

```
(gdb) python from libptmalloc import *
```

Note: you can add this command to your gdbinit:

```
echo "python from libptmalloc import *" >> ~/.gdbinit
```

## Use without installation

If you don't want to install it globally, you can just source this file:

```
(gdb) source libptmalloc/pyptmalloc-dev.py
```

If you need to modify the libptmalloc and reload it in your debugger, please refer to [DevelopmentGuide.md](DevelopmentGuide.md).
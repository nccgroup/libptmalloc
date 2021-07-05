<!-- vim-markdown-toc GFM -->

* [gdb/Python versions](#gdbpython-versions)
* [glibc/ptmalloc versions](#glibcptmalloc-versions)

<!-- vim-markdown-toc -->

# gdb/Python versions

libptmalloc currently works with any gdb version that supports Python >= 3.5. Note that if you use the `dev` branch, you'll need Python >= 3.7, see [DevelopmentGuide.md](DevelopmentGuide.md) for more information.

# glibc/ptmalloc versions

The goal of libptmalloc is to support all ptmalloc and glibc versions.

That being said, it has only been tested extensively on a limited number of versions. If you encounter an error when using it, please create an issue or do a pull request.

We have used it extensively on the following versions:

| Linux distribution | Binary/libc architecture | glibc version | Package | tcache | 
| -- | -- | -- | -- | -- |
| Centos 7 x64 | x64 | 2.17 | glibc-2.17-322.el7_9 | No |
| Photon 1.0 x64 | x64 | 2.22 | glibc-2.22-26.ph1 | No |
| Ubuntu 18.04 x64 | x86 | 2.27 | libc6-i386-2.27-3ubuntu1.4 | Yes |
| Ubuntu 18.04 x64 | x64 | 2.27 | libc6-2.27-3ubuntu1.4 | Yes |
| Photon 3.0 x64 | x64 | 2.28 | glibc-2.28-13.ph3 | No (disabled) |

The above list will be updated once we test more versions. Feel free to report
any additional working version so we add it to the list.
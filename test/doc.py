# -*- coding: future_fstrings -*-
import gdb

debug = False
def debug_print(s, end=None):
    if debug:
        print(s, end=end)

def print_title(title, level=1):
    print("#"*level + " " + title)
    print("")

def execute_and_log(command, max_lines=-1):
    print("```")
    print(f"(gdb) {command}")
    output = gdb.execute(command, from_tty=True, to_string=True)
    if max_lines > 0:
        output = "\n".join(output.split("\n")[:max_lines]) + "\n"
    print(output, end="")
    if max_lines > 0:
        print("...")
    print("```")
    print("")

print_title("Usage", 1)

print_title("libptmalloc commands", 2)
print("""The `pthelp` command lists all the commands provided by libptmalloc:
""")
execute_and_log("pthelp")

print_title("Commands' usage", 2)
print("""Each command has detailed usage that you can print using `-h`:
""")
execute_and_log("ptfree -h")

print_title("Common usage and example", 1)

print_title("ptconfig", 2)
print("""The first thing to make sure when using libptmalloc is to have the 
right glibc version configured in `libptmalloc`.

Note we could automatically detect the ptmalloc version (hence glibc) by pattern
matching on the ptmalloc structures but it is not implemented in libptmalloc yet.

The configured glibc version can be defined in the `libptmalloc.cfg` file:
""")

print("```")
print("".join(open("../libptmalloc/libptmalloc.cfg", "r").readlines()[:3]))
print("""```
""")

print("""It will then reflect using the `ptconfig` command:
""")

execute_and_log("ptconfig")

print("""You can also change it:
""")

execute_and_log("ptconfig -v 2.27")


print_title("ptarena", 2)
print("""We list all the arenas:
""")
execute_and_log("ptarena -l")

print("""We show the arena fields:
""")
execute_and_log("ptarena")

print("""We show more fields:
""")
execute_and_log("ptarena -v")

print("""We show the 2nd arena by specifying its address:
""")
execute_and_log("ptarena 0x7ffff0000020 -v")

print_title("ptlist", 2)
print("""We list all the chunks linearly in an arena. 
By default it prints one line per chunk:
""")
execute_and_log("ptlist 0x7ffff0000020")

print("""Note: The `ptlist` commands support a lot of features from
the `ptchunk` command.
""")

print_title("ptchunk", 2)

print_title("Allocated chunk", 3)
print("""We print one allocated chunk:
""")
execute_and_log("ptchunk 0x5555557998e0")
print("""We print the same allocated chunk with its header and data:
""")
execute_and_log("ptchunk 0x5555557998e0 -v -x")

print_title("Free chunk in regular bin", 3)
print("""We print one free chunk:
""")
execute_and_log("ptchunk 0x555555799ab0")
print("""We print the same free chunk with its header and data:
""")
execute_and_log("ptchunk 0x555555799ab0 -v -x")

print_title("Printing multiple chunks", 3)
print("""We print multiple chunks. You can limit the number of chunks being printed:
""")
execute_and_log("ptchunk 0x5555557998e0 -c 5")
print("""We differentiate chunks that are allocated `M`, freed in an 
unsorted/small/large bin `F`, freed in the fast bin `f` or freed in the tcache bin `t`.
""")

print_title("Combining options", 3)
print("""By combininig all options:
""")
execute_and_log("ptchunk 0x5555557998e0 -c 3 -v -x")

# Switch back to the main arena to get more output in the doc
gdb.execute("ptarena 0x7ffff7baec40", from_tty=True, to_string=True)

print_title("ptbin", 2)
print("""We print all the unsorted/small/large bins. By default it won't print 
the empty bins:
""")
execute_and_log("ptbin")
print("""We print all the bins:
""")
execute_and_log("ptbin -v", max_lines=11)
print("""We print all the chunks in a particular bin:
""")
execute_and_log("ptbin -i 8")

print_title("ptfast", 2)
print("""We print all the fast bins. By default it won't print 
the empty bins:
""")
execute_and_log("ptfast")
# print("""We print all the bins:
# """)
# execute_and_log("ptfast -v", max_lines=8)
print("""We print all the chunks in a particular bin. Note how we limit the number of chunks shown:
""")
execute_and_log("ptfast -i 5 -c 3")

print_title("pttcache", 2)
print("""We print all the tcache bins. By default it won't print 
the empty bins:
""")
execute_and_log("pttcache", max_lines=13)
print("""We print all the chunks in a particular bin:
""")
execute_and_log("pttcache -i 7")

print_title("ptfree", 2)
print("""It prints all the bins by combining the output of `ptbin`, `ptfast` and 
`pttcache`. It is quite verbose so we won't include an example here.
""")

print_title("ptstats", 2)
print("""We print memory statistics for all the arenas:
""")
execute_and_log("ptstats")

print_title("ptmeta", 2)

print("""We first notice this chunk holds the libgcc path:
""")

execute_and_log("ptchunk 0x7ffff0001400 -v -x")

print("""The 'ptmeta command is more advanced and allows to associate user-defined metadata
for given chunks' addresses. E.g. you can add a tag as metadata:
""")
execute_and_log("ptmeta add 0x7ffff0001400 tag \"libgcc path\"")
print("""Then it can be show within other commands:
""")
execute_and_log("ptchunk 0x7ffff0001400 -M tag")
print("""Note: You can also associate a backtrace as metadata, which allows to
write your own heap tracer tool
""")


print_title("Cache", 1)
print("""In order to speed up the execution of commands, libptmalloc caches
the ptmalloc structures as well as the addresses of the chunks in specific bins
when you execute certain commands.
""")

execute_and_log("ptfast 0x7ffff7baec40")

print("""That being said, by default, it won't use the cache, to avoid any misleading info:
""")
execute_and_log("ptfast")
print("""If you want to use the cache, when you know nothing has changed since the
last cached information, you can use the following:
""")
execute_and_log("ptfast --use-cache")

print_title("Advanced usage", 1)

print_title("Searching chunks", 2)
print("""By default, searching will show all chunks but show a match/no-match suffix.
Because we are limiting the number of chunks, and even the non-match, 
we see there is only one match:
""")
execute_and_log("ptlist -s \"GGGG\" -c 9")

print("""If you only want to show matches, you use the following. Note how the 
no-matching chunks are not shown anymore:
""")
execute_and_log("ptlist -s \"GGGG\" -c 2 --match-only")

print("""Analyzing the content, we see the value was found in the chunks header
in the second chunk:
""")
execute_and_log("ptlist -s \"GGGG\" -c 2 --match-only -v -x")

print("""To ignore the chunks headers, we use the following. We see a different
second chunk is shown:
""")
execute_and_log("ptlist -s \"GGGG\" -c 2 --match-only -v -x --skip")

print_title("Printing chunks of specific type(s)", 2)

print("""We print chunks linearly, limiting to 10 chunks, and highlighting tcache free chunks
and regular bin free chunks:
""")
execute_and_log("ptlist -c 10 -I \"t,F\"")

print("""We filter to only show the highlighted chunks, resulting in skipping other types of chunks:
""")
execute_and_log("ptlist -c 10 -I \"t,F\" --highlight-only")

print_title("Detailed commands' usage", 1)
print("""We list all the commands' complete usage as a reference.
""")

print_title("ptconfig usage", 2)
execute_and_log("ptconfig -h")
print_title("ptmeta usage", 2)
execute_and_log("ptmeta -h")
execute_and_log("ptmeta add -h")
execute_and_log("ptmeta del -h")
execute_and_log("ptmeta list -h")
execute_and_log("ptmeta config -h")
print_title("ptarena usage", 2)
execute_and_log("ptarena -h")
print_title("ptparam usage", 2)
execute_and_log("ptparam -h")
print_title("ptlist usage", 2)
execute_and_log("ptlist -h")
print_title("ptchunk usage", 2)
execute_and_log("ptchunk -h")
print_title("ptbin usage", 2)
execute_and_log("ptbin -h")
print_title("ptfast usage", 2)
execute_and_log("ptfast -h")
print_title("pttcache usage", 2)
execute_and_log("pttcache -h")
print_title("ptfree usage", 2)
execute_and_log("ptfree -h")
print_title("ptstats usage", 2)
execute_and_log("ptstats -h")


print_title("Comparison with other tools", 1)

print_title("libheap", 2)
print("""libptmalloc is heavily based on other tools like 
[libheap](https://github.com/cloudburst/libheap) even though a lot has been
changed or added.

The following table shows differences:

| libheap          | libptmalloc      | Note |
|------------------|------------------|------|
| print_bin_layout | ptbin -i <index> | print_bin_layout only includes small bins. ptbin also includes unsorted and large bins |
| heapls | ptlist |      |
| heaplsc | ptlist --compact |      |
| mstats | ptstats |      |
| smallbins | ptbin | ptbin also includes unsorted and large bins |
| fastbins | ptfast |      |
| N/A | pttcache |      |
| freebin | ptfree | ptfree also includes tcache bins |
""")

print_title("Notes", 1)
print("""This documentation is automatically generated by [doc.sh](../test/doc.sh). 
This also allows people to replicate the commands manually into a debugger
""")
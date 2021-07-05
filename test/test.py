import gdb

def execute(command, log=False):
    output = gdb.execute(command, from_tty=True, to_string=True)
    if log:
        print(output)

execute("ptfree", log=True)
execute("q")
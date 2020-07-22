class pydbg:
    def __init__(self, debugger):
        self.debugger = debugger

    def format_address(self, value):
        return self.debugger.format_address(value)

    def get_heap_address(self, mp=None):
        return self.debugger.get_heap_address(mp)

    def get_inferior(self):
        return self.debugger.get_inferior()

    def get_size_sz(self):
        return self.debugger.get_size_sz()

    def read_memory(self, address, length):
        return self.debugger.read_memory(address, length)

    def parse_variable(self, variable):
        """Parse and evaluate an gdb variable expression"""
        return self.debugger.parse_variable(variable)

    def read_variable(self, variable):
        return self.debugger.read_variable(variable)

    def read_variable_address(self, variable):
        return self.debugger.read_variable_address(variable)

    def string_to_argv(self, arg):
        return self.debugger.string_to_argv(arg)

    def write_memory(self, address, buf, length=None):
        return self.debugger.write_memory(address, buf, length)

    def execute(self, cmd, to_string=True):
        return self.debugger.execute(cmd, to_string=to_string)

    def search(
        self, start_address, end_address, search_for, width="32", to_string=True
    ):
        return self.debugger.search(
            start_address, end_address, search_for, width=width, to_string=to_string
        )

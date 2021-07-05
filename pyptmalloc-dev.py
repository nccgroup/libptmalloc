# -*- coding: future_fstrings -*-
import os
import sys

# Add the root path
module_path = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
if module_path not in sys.path:
    #print("DEBUG: adding module path...")
    sys.path.insert(0, module_path)
#print(sys.path) # DEBUG

# We need that after the above so it finds it
from libptmalloc import *

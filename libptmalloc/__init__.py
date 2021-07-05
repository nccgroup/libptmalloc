# -*- coding: future_fstrings -*-
import sys
import logging

from libptmalloc import logger
from libptmalloc import pyptmalloc as pyp

try:
    log
except:
    log = logging.getLogger("libptmalloc")
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logger.MyFormatter(datefmt="%H:%M:%S"))
    log.addHandler(handler)

# This allows changing the log level and reloading in gdb even if the logger was already defined
# XXX - however this file is not reloaded early when we reload in gdb, so we need to re-source in gdb 2x
# for the logger level to be changed atm
#log.setLevel(logging.TRACE) # use for debugging reloading .py files only
#log.setLevel(logging.DEBUG) # all other types of debugging
log.setLevel(logging.NOTSET)

if log.isEnabledFor(logging.TRACE):
    log.warning(f"logging TRACE enabled")
elif log.isEnabledFor(logging.DEBUG):
    log.warning(f"logging DEBUG enabled")
# elif log.isEnabledFor(logging.INFO):
#     log.warning(f"logging INFO enabled")
# elif log.isEnabledFor(logging.WARNING):
#     log.warning(f"logging WARNING enabled")

log.trace("libptmalloc/__init__.py")

pyp.pyptmalloc()

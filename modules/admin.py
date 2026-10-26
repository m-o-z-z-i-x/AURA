# ---------------------------------------------------------------------------- #
# DESCRIPTION: administrator check and elevated relaunch through ShellExecuteW
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import sys
import ctypes
import subprocess

from os import getcwd, path

import modules.logger as logger

from modules.paths import exePath, isFrozen
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
def isAdmin():
  # a failing shell call means the token cannot be proven elevated, so report False
  try:
    return bool(ctypes.windll.shell32.IsUserAnAdmin())
  except Exception:
    return False

def buildParams(args):
  # ShellExecuteW takes one string. list2cmdline quotes and escapes it the way the c runtime parses it back
  return subprocess.list2cmdline(args)

def resolveTarget(frozen):
  # frozen builds relaunch the exe the user started. from source prefer pythonw.exe so no console appears
  if frozen:
    return str(exePath()), buildParams(sys.argv[1:])

  pythonw = path.join(path.dirname(sys.executable), "pythonw.exe")
  target = pythonw if path.exists(pythonw) else sys.executable

  return target, buildParams([path.abspath(sys.argv[0]), *sys.argv[1:]])

def relaunchAsAdmin():
  # returns True when the elevated instance started. a declined UAC prompt returns False
  target, params = resolveTarget(isFrozen())

  try:
    # the result is an HINSTANCE, so without a pointer restype a 64-bit value is cut to an int
    ctypes.windll.shell32.ShellExecuteW.restype = ctypes.c_void_p
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params, getcwd(), 1) # sw_shownormal
  except Exception as e:
    logger.exception(e)

    return False

  return (result or 0) > 32 # values up to 32 are shellexecute error codes
# ---------------------------------------------------------------------------- #
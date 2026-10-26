# ---------------------------------------------------------------------------- #
# DESCRIPTION: where the program lives, from source and as a nuitka onefile exe
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import sys

from pathlib import Path
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
def isFrozen():
  # nuitka sets __compiled__ in module globals instead of sys.frozen
  return bool(getattr(sys, "frozen", False)) or "__compiled__" in globals()

def exeDirectory():
  # a onefile exe unpacks to a temp folder, so sys.executable and __file__ point there while the
  # state files belong next to the original exe. containing_dir is absolute, argv[0] may not be
  compiled = globals().get("__compiled__")

  return Path(directory).resolve() if (directory := getattr(compiled, "containing_dir", None)) else Path(sys.argv[0]).resolve().parent

def exePath():
  # the exe the user started, which is the one to elevate. the unpacked python.exe would not carry the program
  compiled = globals().get("__compiled__")
  name = Path(getattr(compiled, "original_argv0", None) or sys.argv[0]).name

  return exeDirectory() / name
# ---------------------------------------------------------------------------- #
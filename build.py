# ---------------------------------------------------------------------------- #
# DESCRIPTION: builds the standalone executable with nuitka and upx
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import sys

from os import path
from subprocess import run

# custom
from modules.metadata import AUTHOR, APP_NAME, APP_VERSION, DESCRIPTION
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
ROOT = path.dirname(path.abspath(__file__))
SCRIPTS = path.join(ROOT, ".venv", "Scripts")
WINTUN_DIR = path.join(ROOT, "drivers", "wintun")
WINTUN_DLL = path.join(WINTUN_DIR, "wintun.dll")
WINTUN_LICENSE = path.join(WINTUN_DIR, "LICENSE.txt")

# the exe cannot connect without the driver library, so a build without it is refused up front
if not path.isfile(WINTUN_DLL):
  sys.exit("drivers/wintun/wintun.dll is missing: it is part of the repository, restore it with git")

# regenerate the derived files so the build never ships a stale gui or resource bundle
run([path.join(SCRIPTS, "pyuic5"), "./ui/gui.ui", "-o", "./gui.py", "--from-imports"], check = True, cwd = ROOT)
run([path.join(SCRIPTS, "pyrcc5"), "./res/qrc/resources.qrc", "-o", "./modules/resources.py"], check = True, cwd = ROOT)

# main.py imports the bundle itself, so the relative import pyuic5 appends cannot resolve
with open(path.join(ROOT, "gui.py"), encoding = "utf-8") as file:
  lines = [line for line in file.read().splitlines() if "import resources_rc" not in line]

with open(path.join(ROOT, "gui.py"), "w", encoding = "utf-8", newline = "\n") as file:
  file.write("\n".join(lines))

with open(path.join(ROOT, "modules", "resources.py"), encoding = "utf-8") as file:
  bundle = file.read().rstrip("\r\n")

with open(path.join(ROOT, "modules", "resources.py"), "w", encoding = "utf-8", newline = "\n") as file:
  file.write(bundle)

command = [
  sys.executable, "-m", "nuitka", # invoke nuitka with the current venv interpreter

  # compilation options
  "--standalone", # create self-contained distribution
  "--onefile", # create single executable
  "--windows-console-mode=disable", # disable console for pyqt5 app
  "--windows-uac-admin", # ask for administrator rights at launch, the tunnel needs them

  # compiler options
  "--mingw64", # use mingw64 compiler
  "--enable-plugin=pyqt5", # enable pyqt5 plugin

  # output configuration
  "--output-dir=dist", # build directory
  f"--output-filename={APP_NAME}", # final executable name

  # windows metadata
  "--windows-icon-from-ico=res/icons/logo.ico", # application icon
  f"--product-name={APP_NAME}", # product name
  f"--file-version={APP_VERSION}", # file version
  f"--product-version={APP_VERSION}", # product version
  f"--copyright={AUTHOR}", # copyright info
  f"--file-description={DESCRIPTION}", # file description

  # dependency control
  f"--include-data-files={WINTUN_DLL}=drivers/wintun/wintun.dll", # pack the wintun driver library
  f"--include-data-files={WINTUN_LICENSE}=drivers/wintun/LICENSE.txt", # pack its license, required by redistribution

  # optimization
  "--enable-plugin=upx", # enable upx compression
  "--upx-binary=" + path.join(ROOT, "tools", "upx"), # custom upx path

  # debugging and reporting
  "--report=logs/compilation-report.xml", # generate build report

  "main.py"
]

run(command, check = True, cwd = ROOT)
# ---------------------------------------------------------------------------- #
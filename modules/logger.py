# ---------------------------------------------------------------------------- #
# DESCRIPTION: custom logger for execution reports with file and line context
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import logging

from os import path, makedirs
from traceback import extract_tb

from modules.metadata import APP_NAME
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
LOG_FILE_PATH = "./logs/execution-report.log"
LOG_DIR = path.dirname(LOG_FILE_PATH)

def ensureDir(directory):
  # create the directory (with parents) if it does not exist. return success, never raise
  # use this for app-owned paths (logs, caches) that should be created silently when missing
  if not directory:
    return True

  try:
    makedirs(directory, exist_ok = True)

    return True
  except Exception:
    return False

def _buildHandler():
  # try to attach a file handler. when the directory or file cannot be created fall back to a
  # NullHandler so logging degrades quietly instead of crashing the app
  if ensureDir(LOG_DIR):
    try:
      handler = logging.FileHandler(LOG_FILE_PATH, mode = "a", encoding = "utf-8")

      handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s -- %(message)s",
        datefmt = "%Y-%m-%d %H:%M:%S"
      ))

      return handler
    except Exception:
      pass

  return logging.NullHandler()

_logger = logging.getLogger(APP_NAME.lower())

_logger.setLevel(logging.DEBUG)

_logger.propagate = False

if not _logger.handlers:
  _logger.addHandler(_buildHandler())

def exception(err):
  tb = extract_tb(err.__traceback__) if err.__traceback__ else []

  if tb:
    filename, line = tb[-1][:2]
    filename = path.basename(filename)

    _logger.error(f"[FILE] {filename} -- [LINE] {line}: {err}")
  else:
    _logger.error(str(err))

def warning(msg):
  _logger.warning(msg)

def info(msg):
  _logger.info(msg)
# ---------------------------------------------------------------------------- #
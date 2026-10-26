# ---------------------------------------------------------------------------- #
# DESCRIPTION: state file of everything a session changed, swept on the next start
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import os
import re
import json
import ipaddress

from pathlib import Path
from dataclasses import dataclass, field, asdict

import modules.logger as logger

from modules.metadata import APP_NAME
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
RECOVERY_PATH = Path("./recovery.json")

@dataclass
class RecoveryState:
  routes: list[dict] = field(default_factory = list)
  adapterName: str = ""
  dnsInterfaces: list[str] = field(default_factory = list)

def saveRecovery(state):
  # write next to the target and swap it in, so a crash never leaves half a file
  temporary = RECOVERY_PATH.with_name(RECOVERY_PATH.name + ".tmp")

  try:
    temporary.write_text(json.dumps(asdict(state), indent = 2), encoding = "utf-8")
    os.replace(temporary, RECOVERY_PATH)

    return True
  except (OSError, ValueError, TypeError):
    try:
      temporary.unlink()
    except OSError:
      pass

    return False

def _isInt(value):
  return isinstance(value, int) and not isinstance(value, bool)

def _isIpv4(value):
  try:
    return isinstance(value, str) and bool(ipaddress.IPv4Address(value))
  except ValueError:
    return False

def _validRoute(route):
  # the elevated sweep acts on this file, so a route is trusted only in the exact shape network.py writes
  return (
    isinstance(route, dict)
    and _isIpv4(route.get("destination"))
    and _isInt(route.get("prefix")) and 0 <= route["prefix"] <= 32
    and _isInt(route.get("interfaceIndex"))
    and _isIpv4(route.get("gateway"))
    and _isInt(route.get("metric"))
  )

def _readState(data):
  # a wrong-typed or foreign field falls back to its default instead of rejecting the whole file
  # only this program's own adapter and dns entries are acted on, whatever a hand-edited file says
  routes = data.get("routes")
  adapterName = data.get("adapterName")
  dnsInterfaces = data.get("dnsInterfaces")

  return RecoveryState(
    routes = [{key: route[key] for key in ("destination", "prefix", "gateway", "interfaceIndex", "metric")} for route in routes if _validRoute(route)] if isinstance(routes, list) else [],
    adapterName = adapterName if adapterName == APP_NAME else "",
    dnsInterfaces = [item for item in dnsInterfaces if isinstance(item, str) and re.fullmatch(rf"{re.escape(APP_NAME)}:\d+", item)] if isinstance(dnsInterfaces, list) else []
  )

def loadRecovery():
  # a missing or empty file is the normal case. only unreadable content is logged
  try:
    content = RECOVERY_PATH.read_text(encoding = "utf-8")
  except FileNotFoundError:
    return None
  except (OSError, UnicodeError):
    logger.warning("recovery state file is unreadable and was ignored")

    return None

  if not content.strip():
    return None

  try:
    data = json.loads(content)
  except (ValueError, RecursionError):
    data = None

  if not isinstance(data, dict):
    logger.warning("recovery state file is corrupt and was ignored")

    return None

  return _readState(data)

def clearRecovery():
  try:
    RECOVERY_PATH.unlink()
  except OSError:
    pass

def _apply(callback, *args):
  # one failing undo step must not stop the others
  # return the callback result, or False when it raised
  try:
    return callback(*args)
  except Exception as e:
    logger.exception(e)

    return False

def sweep(removeRoute, removeAdapter, restoreDns):
  if (state := loadRecovery()) is None:
    return False

  # undo in reverse of creation: routes and dns sit on the adapter, so they go before it
  for route in state.routes:
    _apply(removeRoute, route)

  for interface in state.dnsInterfaces:
    _apply(restoreDns, interface)

  # the callbacks drop the entries they settled, so what is left in the file is what failed
  remaining = loadRecovery() or RecoveryState()

  if state.adapterName:
    adapterGone = _apply(removeAdapter, state.adapterName) is not False
    remaining.adapterName = "" if adapterGone else state.adapterName

  if remaining.routes or remaining.dnsInterfaces or remaining.adapterName:
    saveRecovery(remaining)
  else:
    clearRecovery()

  return True
# ---------------------------------------------------------------------------- #
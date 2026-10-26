# ---------------------------------------------------------------------------- #
# DESCRIPTION: route table parsing, route planning and netsh based route and dns changes
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import os
import re
import ctypes
import socket
import ipaddress
import subprocess

from pathlib import Path
from dataclasses import dataclass

import modules.logger as logger

from modules.metadata import APP_NAME
from modules.recovery import RecoveryState, saveRecovery, loadRecovery
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
ON_LINK = "0.0.0.0"
TUNNEL_METRIC = 1

class NetworkError(Exception):
  pass

@dataclass
class NetSnapshot:
  gateway: str
  interfaceIndex: int

# the project root from source, nuitka's unpack folder in a onefile exe: modules/ sits one level below either
DLL_PATH = Path(__file__).resolve().parent.parent / "drivers" / "wintun" / "wintun.dll"

def runCommand(args, timeout = 15.0):
  # return (exit code, output). a missing tool or a hang is reported as -1 with a message
  # the full System32 path keeps a planted executable in the working directory from running elevated
  try:
    result = subprocess.run(
      [os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", args[0] + ".exe"), *args[1:]],
      shell = False,
      capture_output = True,
      text = True,
      errors = "replace",
      timeout = timeout,
      creationflags = subprocess.CREATE_NO_WINDOW
    )

    return result.returncode, (result.stdout or "") + (result.stderr or "")
  except (OSError, subprocess.SubprocessError, ValueError, IndexError) as e:
    logger.exception(e)

    return -1, str(e)

def parseRouteTable(text):
  # rows are matched by numeric columns only, so headers and words of any locale are skipped
  rows = []

  for line in str(text).splitlines():
    if not (match := re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(.+?)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s*$", line)):
      continue

    destination, mask, gateway, interfaceAddress, metric = match.groups()

    try:
      ipaddress.IPv4Address(destination)
      ipaddress.IPv4Address(mask)
      ipaddress.IPv4Address(interfaceAddress)
    except ValueError:
      continue

    # a gateway that is not an address ("On-link" in any language) means on-link
    isAddress = re.fullmatch(r"\d+\.\d+\.\d+\.\d+", gateway) is not None

    try:
      if isAddress:
        ipaddress.IPv4Address(gateway)
    except ValueError:
      continue

    rows.append({
      "destination": destination,
      "mask": mask,
      "gateway": gateway if isAddress else "",
      "interfaceAddress": interfaceAddress,
      "metric": int(metric)
    })

  return rows

def _defaultRow(text):
  defaults = [row for row in parseRouteTable(text) if row["destination"] == "0.0.0.0" and row["mask"] == "0.0.0.0" and row["gateway"]]

  return min(defaults, key = lambda row: row["metric"], default = None)

def parseDefaultGateway(text):
  return row["gateway"] if (row := _defaultRow(text)) else ""

def interfaceIndexFor(ip):
  # ask the stack which interface reaches the address, which needs no text parsing at all
  index = ctypes.c_ulong(0)

  try:
    address = ctypes.c_ulong.from_buffer_copy(socket.inet_aton(ip))
    status = ctypes.WinDLL("iphlpapi").GetBestInterface(address, ctypes.byref(index))
  except (OSError, AttributeError):
    return 0

  return index.value if status == 0 else 0

def snapshotDefaultRoute():
  code, output = runCommand(["route", "print", "-4"])

  if code != 0 or not (gateway := parseDefaultGateway(output)):
    raise NetworkError("no default gateway was found, check the network connection")

  if not (index := interfaceIndexFor(gateway)):
    raise NetworkError("the network interface of the default gateway was not found")

  return NetSnapshot(gateway = gateway, interfaceIndex = index)

def _routeDict(destination, prefix, gateway, interfaceIndex, metric):
  return {"destination": destination, "prefix": prefix, "gateway": gateway, "interfaceIndex": interfaceIndex, "metric": metric}

def planRoutes(profile, serverIp, snapshot, tunnelIndex, onLog = None):
  log = onLog or logger.warning

  try:
    server = ipaddress.IPv4Address(serverIp)
  except ValueError:
    raise NetworkError("invalid server address") from None

  if server.is_loopback or server.is_multicast or server.is_unspecified:
    raise NetworkError("invalid server address")

  # the host route goes first, so the tunnel's own packets never enter the tunnel
  routes = [_routeDict(str(server), 32, snapshot.gateway, snapshot.interfaceIndex, TUNNEL_METRIC)]

  if profile.routeAll:
    routes += [_routeDict(destination, 1, ON_LINK, tunnelIndex, TUNNEL_METRIC) for destination in ("0.0.0.0", "128.0.0.0")]

  planned = {(route["destination"], route["prefix"]) for route in routes}

  for entry in profile.extraRoutes:
    try:
      network = ipaddress.ip_network(str(entry).strip(), strict = False)
    except ValueError:
      log(f"extra route {entry!r} is not a valid network and was skipped")

      continue

    if network.version != 4 or network.prefixlen == 0:
      log(f"extra route {entry!r} is not a usable IPv4 network and was skipped")

      continue

    if (key := (str(network.network_address), network.prefixlen)) in planned:
      log(f"extra route {entry!r} duplicates a planned route and was skipped")

      continue

    planned.add(key)
    routes.append(_routeDict(*key, ON_LINK, tunnelIndex, TUNNEL_METRIC))

  return routes

def _recordedState():
  return loadRecovery() or RecoveryState()

def _saveOrRaise(state):
  # a change that cannot be recorded must not be made
  if not saveRecovery(state):
    raise NetworkError("the recovery record could not be saved, nothing was changed")

def _forget(remove):
  # drop a recorded entry again after a failed change. a failed save is logged, not hidden
  state = _recordedState()
  remove(state)

  if not saveRecovery(state):
    logger.warning("the recovery record could not be updated")

def addRoute(destination, prefix, gateway, interfaceIndex, metric):
  route = _routeDict(destination, prefix, gateway, interfaceIndex, metric)

  # record before the change, so a crash right after it still leaves a trace
  state = _recordedState()
  state.routes.append(route)
  _saveOrRaise(state)

  code, output = runCommand(["netsh", "interface", "ipv4", "add", "route", f"prefix={destination}/{prefix}", f"interface={interfaceIndex}", f"nexthop={gateway}", f"metric={metric}", "store=active"])

  if code != 0:
    _forget(lambda current: current.routes.remove(route) if route in current.routes else None)

    raise NetworkError(f"route {destination}/{prefix} could not be added: {output.strip()[:200]}")

  return route

def deleteRoute(route):
  try:
    destination, prefix, gateway, interfaceIndex = route["destination"], route["prefix"], route["gateway"], route["interfaceIndex"]
    code, output = runCommand(["netsh", "interface", "ipv4", "delete", "route", f"prefix={destination}/{prefix}", f"interface={interfaceIndex}", f"nexthop={gateway}", "store=active"])

    if code != 0:
      logger.warning(f"route {destination}/{prefix} was not deleted: {output.strip()[:200]}")

    # the text of a failure is localized and "not found" is normal, but a timeout or a missing tool keeps the record
    if code != -1 and (state := loadRecovery()) and route in state.routes:
      state.routes.remove(route)
      saveRecovery(state)
  except Exception as e:
    logger.exception(e)

def _isIpv4(value):
  try:
    ipaddress.IPv4Address(str(value))

    return True
  except ValueError:
    return False

def setDns(interfaceIndex, servers, adapterName = APP_NAME):
  servers = [server for server in servers if _isIpv4(server)]

  if not servers:
    return

  # the index alone can name another adapter after a reboot, so the entry carries the adapter name
  entry = f"{adapterName}:{interfaceIndex}"
  base = ["netsh", "interface", "ipv4"]
  state = _recordedState()

  if entry not in state.dnsInterfaces:
    state.dnsInterfaces.append(entry)

  _saveOrRaise(state)

  code, output = runCommand([*base, "set", "dnsservers", f"name={interfaceIndex}", "source=static", f"address={servers[0]}", "validate=no"])

  if code != 0:
    _forget(lambda current: current.dnsInterfaces.remove(entry) if entry in current.dnsInterfaces else None)

    raise NetworkError(f"dns could not be set: {output.strip()[:200]}")

  for position, server in enumerate(servers[1:], start = 2):
    code, output = runCommand([*base, "add", "dnsservers", f"name={interfaceIndex}", f"address={server}", f"index={position}", "validate=no"])

    if code != 0:
      raise NetworkError(f"dns server {server} could not be added: {output.strip()[:200]}")

def parseInterfaces(text):
  # keep the text after the three numeric columns, because the state word is localized
  rows = []

  for line in str(text).splitlines():
    if match := re.match(r"^\s*(\d+)\s+\d+\s+\d+\s+(\S.*?)\s*$", line):
      rows.append({"index": int(match.group(1)), "text": match.group(2)})

  return rows

def interfaceHasName(text, index, name):
  # the name is the last column. the state word before it is skipped by a whitespace check
  return any(
    row["index"] == index and row["text"].endswith(name) and (len(row["text"]) == len(name) or row["text"][-len(name) - 1].isspace())
    for row in parseInterfaces(text)
  )

def clearDns(interface, adapterName = APP_NAME):
  # accepts an interface index or a recorded "<adapter>:<index>" entry
  try:
    text = str(interface)
    name, _, index = text.rpartition(":") if ":" in text else (adapterName, "", text)
    entry = f"{name}:{index}"

    code, output = runCommand(["netsh", "interface", "ipv4", "show", "interfaces"])

    if code != 0:
      logger.warning(f"interfaces could not be listed, dns of {entry} was left as it is")

      return

    # a reused index may belong to another adapter now, whose dns must not be touched
    if index.isdigit() and interfaceHasName(output, int(index), name):
      code, output = runCommand(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={index}", "source=dhcp"])

      if code != 0:
        logger.warning(f"dns of interface {entry} was not reset: {output.strip()[:200]}")

      if code == -1:
        return

    if (state := loadRecovery()) and (kept := [item for item in state.dnsInterfaces if item not in (entry, text)]) != state.dnsInterfaces:
      state.dnsInterfaces = kept
      saveRecovery(state)
  except Exception as e:
    logger.exception(e)

def removeAdapter(name):
  # the dll is imported here because wintun imports this module for its commands
  if not Path(DLL_PATH).is_file():
    logger.warning(f"adapter {name} was not removed because wintun.dll is missing")

    return False

  from modules.wintun import WintunAdapter

  return WintunAdapter.removeByName(name, str(DLL_PATH))

def sweepCallbacks():
  return deleteRoute, removeAdapter, clearDns
# ---------------------------------------------------------------------------- #
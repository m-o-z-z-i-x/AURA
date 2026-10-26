# ---------------------------------------------------------------------------- #
# DESCRIPTION: wintun adapter wrapper over wintun.dll with packet read and write
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import uuid
import ctypes

from ctypes import wintypes

import modules.logger as logger

from modules.network import NetworkError, runCommand
from modules.recovery import RecoveryState, saveRecovery, loadRecovery
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
TUNNEL_TYPE = "AURA"

class WintunClosed(Exception):
  pass

class Guid(ctypes.Structure):
  _fields_ = [("raw", ctypes.c_ubyte * 16)]

def _adapterGuid(name):
  # the guid is derived from the name, so a recreated adapter reuses its identity
  return Guid.from_buffer_copy(uuid.uuid5(uuid.UUID("6f1e4c0a-2b7d-5c1e-9a40-7e0f3b9d2a11"), name).bytes_le)

def _bindFunctions(dll):
  # explicit signatures keep 64 bit handles from being truncated to c_int
  handle = ctypes.c_void_p

  signatures = {
    "WintunCreateAdapter": ([wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(Guid)], handle),
    "WintunOpenAdapter": ([wintypes.LPCWSTR], handle),
    "WintunCloseAdapter": ([handle], None),
    "WintunGetAdapterLUID": ([handle, ctypes.POINTER(ctypes.c_uint64)], None),
    "WintunStartSession": ([handle, wintypes.DWORD], handle),
    "WintunEndSession": ([handle], None),
    "WintunGetReadWaitEvent": ([handle], handle),
    "WintunReceivePacket": ([handle, ctypes.POINTER(wintypes.DWORD)], handle),
    "WintunReleaseReceivePacket": ([handle, handle], None),
    "WintunAllocateSendPacket": ([handle, wintypes.DWORD], handle),
    "WintunSendPacket": ([handle, handle], None)
  }

  for name, (argtypes, restype) in signatures.items():
    function = getattr(dll, name)

    # a foreign function object may refuse attribute assignment
    try:
      function.argtypes = argtypes
      function.restype = restype
    except AttributeError:
      pass

class WintunAdapter:
  def __init__(self, loader = ctypes.WinDLL):
    self.loader = loader
    self.dll = None
    self.adapter = None
    self.session = None
    self.readEvent = None
    self.name = ""
    self.index = 0
    self.kernel32 = ctypes.WinDLL("kernel32", use_last_error = True)
    self.kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    self.kernel32.WaitForSingleObject.restype = wintypes.DWORD
    self.iphlpapi = ctypes.WinDLL("iphlpapi")

  @staticmethod
  def _load(dllPath, loader = ctypes.WinDLL):
    try:
      dll = loader(str(dllPath), use_last_error = True)
      _bindFunctions(dll)

      return dll
    except (OSError, AttributeError) as e:
      raise NetworkError(f"wintun.dll could not be loaded from {dllPath}") from e

  @staticmethod
  def removeByName(name, dllPath, loader = ctypes.WinDLL):
    # only an adapter obtained through create is removed by close, and create on an existing name hands it back
    # return whether it was closed, so the caller keeps its record when not
    try:
      dll = WintunAdapter._load(dllPath, loader)
      guid = _adapterGuid(name)

      if adapter := dll.WintunCreateAdapter(name, TUNNEL_TYPE, ctypes.byref(guid)):
        dll.WintunCloseAdapter(adapter)

        return True

      logger.warning(f"adapter {name} could not be opened for removal")
    except Exception as e:
      logger.exception(e)

    return False

  def _lastError(self):
    return ctypes.get_last_error()

  def create(self, name, dllPath):
    self.dll = self._load(dllPath, self.loader)
    self.name = name

    # record the adapter before it exists, so a crash right after leaves a trace
    state = loadRecovery() or RecoveryState()
    state.adapterName = name

    if not saveRecovery(state):
      raise NetworkError("the recovery record could not be saved, nothing was changed")

    # create first: for an existing name it returns that adapter as one this process owns,
    # so close removes it. open is only the fallback and its adapter is merely released
    guid = _adapterGuid(name)
    self.adapter = self.dll.WintunCreateAdapter(name, TUNNEL_TYPE, ctypes.byref(guid)) or self.dll.WintunOpenAdapter(name)

    if not self.adapter:
      raise NetworkError(f"adapter {name} could not be created, check the administrator rights")

    luid = ctypes.c_uint64(0)

    self.dll.WintunGetAdapterLUID(self.adapter, ctypes.byref(luid))

    index = wintypes.ULONG(0)

    if self.iphlpapi.ConvertInterfaceLuidToIndex(ctypes.byref(luid), ctypes.byref(index)) != 0:
      self.close()

      raise NetworkError(f"adapter {name} has no interface index")

    self.index = index.value
    self.session = self.dll.WintunStartSession(self.adapter, 0x400000)

    if not self.session:
      self.close()

      raise NetworkError(f"adapter {name} could not start its session")

    self.readEvent = self.dll.WintunGetReadWaitEvent(self.session)

  def setAddress(self, ip, mtu):
    # a /32 address: routes to the tunnel are on-link, so no peer address is needed
    # a reused adapter may still hold the address, so it is deleted first and that result is ignored
    base = ["netsh", "interface", "ipv4"]

    runCommand([*base, "delete", "address", f"name={self.index}", f"address={ip}"])

    code, output = runCommand([*base, "add", "address", f"name={self.index}", f"address={ip}", "mask=255.255.255.255", "store=active"])

    if code != 0:
      raise NetworkError(f"address {ip} could not be set on the adapter: {output.strip()[:200]}")

    code, output = runCommand([*base, "set", "subinterface", f"interface={self.index}", f"mtu={mtu}", "store=active"])

    if code != 0:
      raise NetworkError(f"mtu {mtu} could not be set on the adapter: {output.strip()[:200]}")

  def read(self, timeoutMs):
    # return one packet, None on timeout, raise WintunClosed when the adapter is going away
    # the reader thread must be joined before close(), the ring is freed by the session end
    session = self.session

    if not session:
      raise WintunClosed("the session is closed")

    for attempt in range(2):
      size = wintypes.DWORD(0)
      packet = self.dll.WintunReceivePacket(session, ctypes.byref(size))

      if packet:
        data = ctypes.string_at(packet, size.value)
        self.dll.WintunReleaseReceivePacket(session, packet)

        return data

      if (error := self._lastError()) != 259:  # error_no_more_items
        raise WintunClosed(f"the session ended with error {error}")

      if attempt == 1:
        return None

      self.kernel32.WaitForSingleObject(self.readEvent, max(0, int(timeoutMs)))

      if self.session is not session:
        raise WintunClosed("the session was closed")

    return None

  def write(self, packet):
    if not (session := self.session) or not packet:
      return False

    buffer = self.dll.WintunAllocateSendPacket(session, len(packet))

    if not buffer:
      return False

    ctypes.memmove(buffer, packet, len(packet))
    self.dll.WintunSendPacket(session, buffer)

    return True

  def close(self):
    session, adapter = self.session, self.adapter
    self.session = None
    self.adapter = None

    if session:
      self.dll.WintunEndSession(session)

    if adapter:
      self.dll.WintunCloseAdapter(adapter)
# ---------------------------------------------------------------------------- #
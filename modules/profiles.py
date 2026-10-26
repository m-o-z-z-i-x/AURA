# ---------------------------------------------------------------------------- #
# DESCRIPTION: connection profiles with DPAPI-protected secrets on disk
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import os
import json
import math
import base64
import ctypes

from ctypes import wintypes
from pathlib import Path
from dataclasses import dataclass, field, asdict, fields
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
PROFILES_PATH = Path("./profiles.json")

# secrets live in memory as plain text and on disk only as these protected keys
SECRET_KEYS = {"password": "passwordProtected", "psk": "pskProtected"}

@dataclass
class Profile:
  name: str = ""
  server: str = ""
  username: str = ""
  # repr is off so a printed or logged profile never shows a secret
  password: str = field(default = "", repr = False)
  psk: str = field(default = "", repr = False)
  ipsecEnabled: bool = True
  routeAll: bool = True
  remember: bool = False
  port: int = 1701
  ikePort: int = 500
  mtu: int = 1400
  authMethods: list[str] = field(default_factory = lambda: ["mschapv2", "chap", "pap"])
  mppe: str = "auto"
  dns: list[str] = field(default_factory = list)
  extraRoutes: list[str] = field(default_factory = list)
  dpdInterval: float = 20.0
  helloInterval: float = 60.0
  ikeId: str = ""
  # inner udp checksum under esp: "zero" sends none, the only value proven against a live server, "auto" computes it
  innerChecksum: str = "zero"

class DataBlob(ctypes.Structure):
  _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

_crypt32 = ctypes.WinDLL("crypt32")
_kernel32 = ctypes.WinDLL("kernel32")

_crypt32.CryptProtectData.argtypes = [
  ctypes.POINTER(DataBlob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
  ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DataBlob)
]
_crypt32.CryptProtectData.restype = wintypes.BOOL
_crypt32.CryptUnprotectData.argtypes = [
  ctypes.POINTER(DataBlob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
  ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DataBlob)
]
_crypt32.CryptUnprotectData.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.LocalFree.restype = ctypes.c_void_p

def _runDpapi(function, data):
  # return the transformed bytes or None, freeing the buffer Windows allocated
  buffer = ctypes.create_string_buffer(data, len(data))
  blobIn = DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
  blobOut = DataBlob()

  if not function(ctypes.byref(blobIn), None, None, None, None, 0x1, ctypes.byref(blobOut)): # 0x1 is cryptprotect_ui_forbidden
    return None

  try:
    return ctypes.string_at(blobOut.pbData, blobOut.cbData)
  finally:
    _kernel32.LocalFree(ctypes.cast(blobOut.pbData, ctypes.c_void_p))

def protectSecret(plain):
  # raise OSError on failure so a secret is never written unprotected by accident
  if not plain:
    return ""

  if (blob := _runDpapi(_crypt32.CryptProtectData, plain.encode("utf-8"))) is None:
    raise OSError("secret protection failed")

  return base64.b64encode(blob).decode("ascii")

def unprotectSecret(blob):
  # any failure yields None and nothing about the content is reported
  try:
    raw = base64.b64decode(blob, validate = True)

    if not raw or (plain := _runDpapi(_crypt32.CryptUnprotectData, raw)) is None:
      return None

    return plain.decode("utf-8")
  except Exception:
    return None

def _isValid(value, default):
  # bool is an int subclass, so it is excluded explicitly for the numeric kinds
  if isinstance(default, bool):
    return isinstance(value, bool)

  if isinstance(default, float):
    # huge integers overflow float() and json also yields nan and infinity
    try:
      return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))
    except (OverflowError, ValueError):
      return False

  if isinstance(default, int):
    return isinstance(value, int) and not isinstance(value, bool) and -2 ** 63 <= value < 2 ** 63

  if isinstance(default, list):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)

  return isinstance(value, type(default))

def _parseProfile(entry, index):
  profile = Profile()

  for item in fields(Profile):
    if item.name in SECRET_KEYS:
      continue

    try:
      if item.name in entry and _isValid(value := entry[item.name], default := getattr(profile, item.name)):
        setattr(profile, item.name, float(value) if isinstance(default, float) else value)
    except Exception:
      continue

  for name, key in SECRET_KEYS.items():
    if isinstance(blob := entry.get(key), str) and (plain := unprotectSecret(blob)) is not None:
      setattr(profile, name, plain)

  if not profile.name:
    profile.name = f"Profile {index}"

  return profile

def _uniqueNames(profiles):
  # later duplicates get a numeric suffix in file order
  taken = set()

  for profile in profiles:
    base, number = profile.name, 2

    while profile.name in taken:
      profile.name, number = f"{base} ({number})", number + 1

    taken.add(profile.name)

def loadProfiles():
  # an unreadable or foreign file yields no profiles and is left untouched until the next save
  try:
    stored = json.loads(PROFILES_PATH.read_text(encoding = "utf-8"))
  except Exception:
    return [], False

  if not isinstance(stored, dict) or not isinstance(entries := stored.get("profiles"), list):
    return [], False

  profiles = []

  for entry in entries:
    if isinstance(entry, dict):
      profiles.append(_parseProfile(entry, len(profiles) + 1))

  _uniqueNames(profiles)

  return profiles, True

def _serialize(profile):
  data = asdict(profile)
  secrets = {name: data.pop(name) for name in SECRET_KEYS}

  if profile.remember:
    data.update({key: protectSecret(secrets[name]) for name, key in SECRET_KEYS.items() if secrets[name]})

  return data

def saveProfiles(profiles):
  # write next to the target and swap it in, so a crash never leaves half a file
  temporary = PROFILES_PATH.with_name(PROFILES_PATH.name + ".tmp")

  try:
    content = json.dumps({"profiles": [_serialize(profile) for profile in profiles]}, indent = 2)
    temporary.write_text(content, encoding = "utf-8")
    os.replace(temporary, PROFILES_PATH)

    return True
  except (OSError, ValueError):
    try:
      temporary.unlink()
    except OSError:
      pass

    return False
# ---------------------------------------------------------------------------- #
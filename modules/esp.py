# ---------------------------------------------------------------------------- #
# DESCRIPTION: esp transport mode packet protection (rfc 4303) for the nat-t path
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import os
import hmac

from struct import pack, unpack
from dataclasses import dataclass, field

from modules.crypto import CIPHERS, cbcDecrypt, cbcEncrypt, prf
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
REPLAY_WINDOW = 64
MAX_SEQUENCE = 0xFFFFFFFF
# hmac-sha1-96 per rfc 2404, hmac-sha2-256-128 per rfc 4868
DEFAULT_ICV = {"sha1": 12, "sha256": 16}

class EspError(Exception):
  # reason is a short key the data path counts drops under, the text carries the detail
  def __init__(self, message, reason = "esp"):
    super().__init__(message)
    self.reason = reason

@dataclass
class EspSa:
  spi: int
  cipher: str
  encKey: bytes = field(repr = False)
  hashName: str
  authKey: bytes = field(repr = False)
  # icv size in bytes, 0 selects the default for hashName
  icvLength: int = 0

  def icvSize(self):
    return self.icvLength or DEFAULT_ICV.get(self.hashName, 0)

def _newIv(size):
  return os.urandom(size)

def _checkSa(sa):
  if sa.cipher not in CIPHERS or sa.hashName not in DEFAULT_ICV:
    raise EspError("unsupported esp algorithm")

  if len(sa.encKey) != CIPHERS[sa.cipher][0] or not 0 <= sa.spi <= MAX_SEQUENCE:
    raise EspError("invalid esp security association")

  if not 4 <= sa.icvSize() <= (20 if sa.hashName == "sha1" else 32):
    raise EspError("invalid esp icv length")

class EspChannel:
  # seal and open both run on the socket thread, so neither needs a lock
  def __init__(self, outSa, inSa):
    _checkSa(outSa)
    _checkSa(inSa)
    self.outSa, self.inSa = outSa, inSa
    self.seq = 0
    self.top = 0
    self.window = 0

  def seal(self, payload, nextHeader):
    if self.seq >= MAX_SEQUENCE:
      raise EspError("sequence number exhausted", "exhausted")

    blockSize = CIPHERS[self.outSa.cipher][1]
    padLength = -(len(payload) + 2) % blockSize
    body = payload + bytes(range(1, padLength + 1)) + bytes((padLength, nextHeader))
    self.seq += 1
    iv = _newIv(blockSize)
    head = pack(">II", self.outSa.spi, self.seq) + iv + cbcEncrypt(self.outSa.cipher, self.outSa.encKey, iv, body)

    return head + prf(self.outSa.hashName, self.outSa.authKey, head)[:self.outSa.icvSize()]

  def open(self, packet):
    sa = self.inSa
    blockSize, icvSize = CIPHERS[sa.cipher][1], sa.icvSize()

    if len(packet) < 8 + 2 * blockSize + icvSize or (len(packet) - 8 - blockSize - icvSize) % blockSize:
      raise EspError(f"esp packet has an invalid length ({len(packet)} bytes)", "length")

    spi, seq = unpack(">II", packet[:8])

    if spi != sa.spi:
      raise EspError(f"esp packet has an unexpected spi 0x{spi:08x}, expected 0x{sa.spi:08x}", "spi")

    signed, icv = packet[:len(packet) - icvSize], packet[len(packet) - icvSize:]

    if not hmac.compare_digest(prf(sa.hashName, sa.authKey, signed)[:icvSize], icv):
      raise EspError(f"esp integrity check failed (spi 0x{spi:08x}, sequence {seq}, {len(packet)} bytes)", "icv")

    self._checkReplay(seq)
    body = cbcDecrypt(sa.cipher, sa.encKey, signed[8:8 + blockSize], signed[8 + blockSize:])
    padLength, nextHeader = body[-2], body[-1]

    if padLength > len(body) - 2 or body[len(body) - 2 - padLength:-2] != bytes(range(1, padLength + 1)):
      raise EspError("esp padding is invalid", "padding")

    return body[:len(body) - 2 - padLength], nextHeader

  def _checkReplay(self, seq):
    # rfc 4303 section 3.4.3: the window moves only after the icv verified
    if seq == 0:
      raise EspError("esp sequence number zero", "replay")

    if seq > self.top:
      shift = seq - self.top
      self.window = ((self.window << shift) | 1) & (2 ** REPLAY_WINDOW - 1)
      self.top = seq

      return

    if (offset := self.top - seq) >= REPLAY_WINDOW:
      raise EspError(f"esp sequence number {seq} below the replay window", "replay")

    if self.window >> offset & 1:
      raise EspError(f"esp packet {seq} replayed", "replay")

    self.window |= 1 << offset
# ---------------------------------------------------------------------------- #
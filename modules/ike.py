# ---------------------------------------------------------------------------- #
# DESCRIPTION: ikev1 initiator (rfc 2409) with pre-shared key main mode, quick mode for an esp
# transport sa carrying l2tp, nat traversal (rfc 3947) and dead peer detection (rfc 3706)
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import hashlib
import hmac
import ipaddress
import socket
import threading
import time

from dataclasses import dataclass
from secrets import randbelow, token_bytes
from struct import pack, unpack, unpack_from

from modules.crypto import CIPHERS, DH_GROUPS, cbcDecrypt, cbcEncrypt, dhGenerate, dhShared, prf
from modules.esp import EspChannel, EspSa
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
HEADER_LENGTH = 28
FLAG_ENCRYPTED = 0x01
MAIN_MODE, INFORMATIONAL, QUICK_MODE = 2, 5, 32
ZERO_COOKIE = bytes(8)

PAYLOAD_SA, PAYLOAD_PROPOSAL, PAYLOAD_TRANSFORM, PAYLOAD_KE, PAYLOAD_ID = 1, 2, 3, 4, 5
PAYLOAD_HASH, PAYLOAD_NONCE, PAYLOAD_NOTIFY, PAYLOAD_DELETE, PAYLOAD_VENDOR = 8, 10, 11, 12, 13
# nat-d and nat-oa payload numbers of rfc 3947 and of the drafts before it
NAT_PAYLOADS = {"rfc": (20, 21), "draft": (130, 131)}

DOI_IPSEC = 1
PROTO_ISAKMP, PROTO_ESP = 1, 3
KEY_IKE = 1
ID_IPV4_ADDR = 1
UDP, L2TP_PORT = 17, 1701

# phase 1 attribute classes of rfc 2409 appendix a, phase 2 ones of rfc 2407 section 4.5
ATTR_CIPHER, ATTR_HASH, ATTR_AUTH, ATTR_GROUP, ATTR_LIFE_TYPE, ATTR_LIFE, ATTR_KEY_LENGTH = 1, 2, 3, 4, 11, 12, 14
ESP_LIFE_TYPE, ESP_LIFE, ESP_ENCAPSULATION, ESP_AUTH, ESP_KEY_LENGTH = 1, 2, 4, 5, 6
AUTH_PSK = 1
LIFE_SECONDS = 1
LIFETIME = 28800

IKE_CIPHERS = {"aes256": (7, 256), "aes128": (7, 128), "3des": (5, 0)}
ESP_CIPHERS = {"aes256": (12, 256), "aes128": (12, 128), "3des": (3, 0)}
IKE_HASHES = {"sha256": 4, "sha1": 2}
ESP_AUTHS = {"sha256": 5, "sha1": 2}

INVALID_ID_INFORMATION, AUTHENTICATION_FAILED = 18, 24
R_U_THERE, R_U_THERE_ACK = 36136, 36137
NOTIFY_NAMES = {
  1: "INVALID-PAYLOAD-TYPE", 14: "NO-PROPOSAL-CHOSEN", 16: "PAYLOAD-MALFORMED", 18: "INVALID-ID-INFORMATION",
  23: "INVALID-HASH-INFORMATION", 24: "AUTHENTICATION-FAILED", 24576: "RESPONDER-LIFETIME", 24578: "INITIAL-CONTACT",
  36136: "R-U-THERE", 36137: "R-U-THERE-ACK"
}

VENDOR_NATT_RFC = hashlib.md5(b"RFC 3947").digest()
VENDOR_NATT_DRAFTS = (hashlib.md5(b"draft-ietf-ipsec-nat-t-ike-02\n").digest(), hashlib.md5(b"draft-ietf-ipsec-nat-t-ike-03").digest())
VENDOR_DPD = bytes.fromhex("afcad71368a1f1c96b8696fc77570100")

NON_ESP_MARKER = bytes(4)
NAT_T_PORT = 4500
NONCE_SIZE = 32

@dataclass
class IkeProposal:
  cipher: str
  hashName: str
  dhGroup: int

DEFAULT_PROPOSALS = [IkeProposal(cipher, hashName, group) for cipher in ("aes256", "aes128", "3des") for hashName in ("sha256", "sha1") for group in (14, 5, 2)]

class IkeError(Exception):
  def __init__(self, reason, field = None):
    super().__init__(reason)
    self.reason, self.field = reason, field

@dataclass
class IkeResult:
  channel: EspChannel
  lifetime: int
  peerPort: int
  # the socket the tunnel uses from now on: the float socket after the move to the server's 4500
  sock: socket.socket

@dataclass
class Packet:
  initiatorCookie: bytes
  responderCookie: bytes
  firstPayload: int
  exchange: int
  flags: int
  messageId: int
  body: bytes
  raw: bytes

  encrypted = property(lambda self: bool(self.flags & FLAG_ENCRYPTED))

def isIke(datagram):
  # on port 4500 ike carries the non-esp marker. esp starts with a non-zero spi and keepalives are one byte
  return len(datagram) >= len(NON_ESP_MARKER) + HEADER_LENGTH and datagram[:4] == NON_ESP_MARKER

def _encodePayloads(payloads):
  # each generic header names the type of the payload after it, the last one names none
  following = [kind for kind, _ in payloads[1:]] + [0]

  if any(len(body) > 0xFFFF - 4 for _, body in payloads):
    raise ValueError("payload too long")

  return b"".join(pack(">BBH", after, 0, 4 + len(body)) + bytes(body) for after, (_, body) in zip(following, payloads))

def _decodePayloads(data, firstType):
  # the first type lives in the isakmp header or the enclosing payload, so the caller passes it
  payloads, offset, kind = [], 0, firstType

  while kind:
    if len(data) - offset < 4:
      raise ValueError("payload header runs past the message")

    following, _, length = unpack_from(">BBH", data, offset)

    if length < 4 or offset + length > len(data):
      raise ValueError("payload length does not fit the message")

    payloads.append((kind, bytes(data[offset + 4:offset + length])))
    offset += length
    kind = following

  return payloads

def _chainLength(payloads):
  return sum(4 + len(body) for _, body in payloads)

def _attribute(kind, value):
  return pack(">HH", 0x8000 | kind, value) if value < 0x10000 else pack(">HH", kind, 4) + value.to_bytes(4, "big")

def _decodeAttributes(data):
  # an ordered list of (class, value), since rfc 2407 section 4.5 lets a class repeat (life type and duration pairs)
  pairs, offset = [], 0

  while offset < len(data):
    if len(data) - offset < 4:
      raise ValueError("attribute runs past the transform")

    kind, value = unpack_from(">HH", data, offset)

    if kind & 0x8000:
      pairs.append((kind & 0x7FFF, value))
      offset += 4
    elif value > 8 or offset + 4 + value > len(data):
      raise ValueError("variable attribute with a bad length")
    else:
      pairs.append((kind, int.from_bytes(data[offset + 4:offset + 4 + value], "big")))
      offset += 4 + value

  return pairs

def _decodeSa(body):
  # [(protocol, spi, [(transform id, attributes)])] for every proposal of an sa payload
  if len(body) < 8 or unpack(">I", body[:4])[0] != DOI_IPSEC:
    raise ValueError("sa payload outside the ipsec domain of interpretation")

  proposals = []

  for kind, proposal in _decodePayloads(body[8:], PAYLOAD_PROPOSAL):
    if kind != PAYLOAD_PROPOSAL or len(proposal) < 4 or len(proposal) < 4 + proposal[2]:
      raise ValueError("malformed proposal payload")

    transforms = []

    for inner, transform in _decodePayloads(proposal[4 + proposal[2]:], PAYLOAD_TRANSFORM):
      if inner != PAYLOAD_TRANSFORM or len(transform) < 4:
        raise ValueError("malformed transform payload")

      transforms.append((transform[1], _decodeAttributes(transform[4:])))

    proposals.append((proposal[1], proposal[4:4 + proposal[2]], transforms))

  return proposals

def _saPayload(protocol, spi, transforms):
  numbered = [(PAYLOAD_TRANSFORM, bytes([number]) + body) for number, body in enumerate(transforms, 1)]
  proposal = pack(">BBBB", 1, protocol, len(spi), len(transforms)) + spi + _encodePayloads(numbered)

  # situation 1 is identity only
  return pack(">II", DOI_IPSEC, 1) + _encodePayloads([(PAYLOAD_PROPOSAL, proposal)])

def _ikeTransform(proposal):
  # transform body without its leading number, which saPayload fills in
  cipherId, keyBits = IKE_CIPHERS[proposal.cipher]
  attributes = [
    (ATTR_CIPHER, cipherId), (ATTR_HASH, IKE_HASHES[proposal.hashName]), (ATTR_AUTH, AUTH_PSK),
    (ATTR_GROUP, proposal.dhGroup), (ATTR_LIFE_TYPE, LIFE_SECONDS), (ATTR_LIFE, LIFETIME)
  ] + ([(ATTR_KEY_LENGTH, keyBits)] if keyBits else [])

  return pack(">BH", KEY_IKE, 0) + b"".join(_attribute(*item) for item in attributes)

def _espTransform(cipher, hashName, encapsulation):
  transformId, keyBits = ESP_CIPHERS[cipher]
  attributes = [
    (ESP_LIFE_TYPE, LIFE_SECONDS), (ESP_LIFE, LIFETIME), (ESP_ENCAPSULATION, encapsulation), (ESP_AUTH, ESP_AUTHS[hashName])
  ] + ([(ESP_KEY_LENGTH, keyBits)] if keyBits else [])

  return pack(">BH", transformId, 0) + b"".join(_attribute(*item) for item in attributes)

def _lifetimeOf(pairs, typeKey, lifeKey):
  # each life type governs the duration after it. only a seconds pair counts, kilobytes pairs are skipped
  lifeType = LIFE_SECONDS

  for kind, value in pairs:
    if kind == typeKey:
      lifeType = value
    elif kind == lifeKey and lifeType == LIFE_SECONDS and value:
      return value

  return LIFETIME

def _buildMessage(initiatorCookie, responderCookie, firstPayload, exchange, flags, messageId, body):
  # 0x10 is isakmp version 1.0
  return pack(">8s8sBBBBII", initiatorCookie, responderCookie, firstPayload, 0x10, exchange, flags, messageId, HEADER_LENGTH + len(body)) + body

def _parsePacket(data):
  if len(data) < HEADER_LENGTH:
    raise ValueError("datagram shorter than an isakmp header")

  # largest datagram accepted
  if len(data) > 16384:
    raise ValueError("oversized datagram")

  initiatorCookie, responderCookie, first, version, exchange, flags, messageId, length = unpack_from(">8s8sBBBBII", data)

  if version >> 4 != 1:
    raise ValueError("unsupported isakmp version")

  if not HEADER_LENGTH <= length <= len(data):
    raise ValueError("isakmp length does not fit the datagram")

  return Packet(initiatorCookie, responderCookie, first, exchange, flags, messageId, bytes(data[HEADER_LENGTH:length]), bytes(data))

def _digest(hashName, data):
  return hashlib.new(hashName, data).digest()

def _expandKey(hashName, skeyidE, size):
  # rfc 2409 appendix b: K1 = prf(SKEYID_e, 0), Kn = prf(SKEYID_e, Kn-1) when SKEYID_e is too short
  if len(skeyidE) >= size:
    return skeyidE[:size]

  material, block = b"", b"\x00"

  while len(material) < size:
    block = prf(hashName, skeyidE, block)
    material += block

  return material[:size]

def _firstOf(payloads):
  values = {}

  for kind, body in payloads:
    values.setdefault(kind, body)

  return values

def _notifyParts(body):
  if len(body) < 8 or len(body) < 8 + body[5]:
    raise ValueError("notify payload too short")

  return body[4], unpack(">H", body[6:8])[0], body[8:8 + body[5]], body[8 + body[5]:]

def _notifyBody(protocol, spi, code, data = b""):
  return pack(">IBBH", DOI_IPSEC, protocol, len(spi), code) + spi + data

def _describe(e):
  # own ValueError texts name the defect. anything else is reduced to its type so no data leaks
  return str(e) if type(e) is ValueError else type(e).__name__

def _describeId(body):
  # an id or nat-oa body (rfc 2407 section 4.6.2, rfc 3947 section 5.2) as protocol/port and address
  if len(body) < 8 or body[0] != ID_IPV4_ADDR:
    return f"id type {body[0]}" if body else "empty id"

  protocol, port, address = body[1], unpack(">H", body[2:4])[0], socket.inet_ntoa(body[4:8])

  return f"{protocol}/{port} {address}" if protocol or port else address

def _newCookie():
  cookie = token_bytes(8)

  return cookie if cookie[:4] != NON_ESP_MARKER else _newCookie()

def _newMessageId():
  return randbelow(0xFFFFFFFF) + 1

class IkeSession:
  def __init__(self, sock, server, psk, proposals, ikeId, onLog, floatSock = None, clock = time.monotonic, sleep = time.sleep, dpdTimeout = 30.0):
    self.sock, self.floatSock, self.server = sock, floatSock, (str(server[0]), int(server[1]))
    self.psk = psk.encode("utf-8") if isinstance(psk, str) else bytes(psk)
    self.proposals = list(proposals) or list(DEFAULT_PROPOSALS)

    if any(p.cipher not in IKE_CIPHERS or p.hashName not in IKE_HASHES or p.dhGroup not in DH_GROUPS for p in self.proposals):
      raise ValueError("unsupported ike proposal")

    self.ikeId, self.onLog, self.clock, self.sleep, self.dpdTimeout = ikeId or "", onLog, clock, sleep, dpdTimeout
    self.lock = threading.Lock()
    self.stage = "idle"
    self.established = self.floated = self.peerDpd = self.peerDeleted = self.dpdSkipLogged = False
    self.natVersion = None
    self.initiatorCookie = self.responderCookie = ZERO_COOKIE
    self.deadline = 0.0
    self.lifetime = 0
    self.establishedAt = self.dpdPendingSince = self.lastDpdSent = None
    self.dpdSequence = randbelow(0x7FFFFFFF)
    self.iv = self.quickReplyRaw = self.quickAck = None

  def _log(self, message):
    self.onLog(f"IKE {message}")

  # NEGOTIATION ------------------------------------------------------------ #
  def negotiate(self, timeout):
    self.deadline = self.clock() + timeout

    try:
      self._prepare()
      self._mainMode()

      return self._quickMode()
    except IkeError as e:
      self.stage = "failed"
      self._log(f"negotiation failed: {e.reason}")
      raise
    except Exception as e:
      self.stage = "failed"
      self._log(f"negotiation failed ({type(e).__name__})")
      raise IkeError("IKE negotiation failed unexpectedly") from None

  def _prepare(self):
    host, self.serverPort = self.server

    try:
      self.serverIp = str(ipaddress.IPv4Address(host))
    except ValueError:
      try:
        self.serverIp = socket.gethostbyname(host)
      except OSError:
        raise IkeError("server address could not be resolved", "server") from None

    host, self.localPort = self.sock.getsockname()[:2]

    if host in ("", "0.0.0.0"):
      # a connected udp socket reveals the interface address the system routes to the server through
      try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
          probe.connect((self.serverIp, self.serverPort))
          host = probe.getsockname()[0]
      except OSError:
        raise IkeError("no network route to the server", "server") from None

    self.localIp = host

  def _exchange(self, message, accept, name):
    nextSend = None

    while True:
      now = self.clock()

      if now >= self.deadline:
        raise self._silenceError()

      if nextSend is None or now >= nextSend:
        if nextSend is not None:
          self._log(f"retransmitting {name}")

        self._transmit(message)
        # retransmit after two seconds
        nextSend = now + 2.0

      if (datagram := self._receive(min(nextSend, self.deadline) - now)) is None:
        continue

      try:
        packet = _parsePacket(datagram)
        self._checkCookies(packet)
        result = accept(packet)
      except IkeError:
        raise
      except Exception as e:
        self._log(f"dropped a packet ({_describe(e)})")
        continue

      if result is not None:
        return result

  def _silenceError(self):
    if self.stage == "auth":
      # the server answered the clear messages but not the one encrypted with the key, the classic wrong psk sign
      return IkeError("wrong pre-shared key", "psk")

    return IkeError("server did not answer", "server")

  def _transmit(self, message):
    try:
      if self.floated:
        self.floatSock.sendto(NON_ESP_MARKER + message, (self.serverIp, NAT_T_PORT))
      else:
        self.sock.sendto(message, (self.serverIp, self.serverPort))
    except OSError as e:
      self._log(f"send failed ({type(e).__name__})")

  def _receive(self, wait):
    sock = self.floatSock if self.floated else self.sock

    try:
      sock.settimeout(max(wait, 0.001))
      data, address = sock.recvfrom(65535)
    except TimeoutError:
      return None
    except OSError as e:
      # windows reports an icmp port unreachable as an error on the next udp receive
      self._log(f"socket error while waiting ({type(e).__name__})")
      self.sleep(max(min(wait, 0.25), 0.0))

      return None

    if address[0] != self.serverIp:
      self._log("dropped a datagram from another address")

      return None

    if self.floated:
      if not isIke(data):
        self._log("dropped a non-IKE datagram on the NAT-T port")

        return None

      data = data[len(NON_ESP_MARKER):]

    return data

  def _checkCookies(self, packet):
    if packet.initiatorCookie != self.initiatorCookie:
      raise ValueError("initiator cookie is not ours")

    # a clear notify may carry a zero responder cookie when the server refuses message 1
    if self.responderCookie != ZERO_COOKIE and packet.responderCookie != self.responderCookie and (packet.encrypted or packet.responderCookie != ZERO_COOKIE):
      raise ValueError("responder cookie is not ours")

  def _message(self, exchange, messageId, payloads):
    return _buildMessage(self.initiatorCookie, self.responderCookie, payloads[0][0], exchange, 0, messageId, _encodePayloads(payloads))

  def _encrypt(self, plain, iv):
    sealed = cbcEncrypt(self.cipher, self.encKey, iv, plain + bytes(-len(plain) % self.blockSize))

    return sealed, sealed[-self.blockSize:]

  def _decrypt(self, sealed, iv):
    if not sealed or len(sealed) % self.blockSize:
      raise ValueError("encrypted body is not whole cipher blocks")

    return cbcDecrypt(self.cipher, self.encKey, iv, sealed), sealed[-self.blockSize:]

  def _checkNotifies(self, payloads):
    # clear notifies are unauthenticated, but a refusing server has no other way to say so
    for kind, body in payloads:
      if kind != PAYLOAD_NOTIFY:
        continue

      protocol, code, spi, data = _notifyParts(body)
      self._log(f"server sent notify {NOTIFY_NAMES.get(code, code)}")

      # 14 is no-proposal-chosen
      if code == 14:
        raise IkeError("server rejected every proposed cipher combination")

      # in quick mode hash_r has already proved the psk, so these refusals are about policy instead
      if self.stage not in ("policy", "keys", "auth"):
        if code == INVALID_ID_INFORMATION:
          raise IkeError("server refused the L2TP traffic selectors")

        if code == AUTHENTICATION_FAILED:
          raise IkeError("server refused the IPsec security association")
      elif code == INVALID_ID_INFORMATION:
        raise IkeError("server did not accept the IKE identity", "psk")
      # notifies responders send when they could not decrypt or verify message 5
      elif code == AUTHENTICATION_FAILED or code in (1, 16, 23, 24) and self.stage == "auth":
        raise IkeError("wrong pre-shared key", "psk")

    return None

  # MAIN MODE --------------------------------------------------------------- #
  def _mainMode(self):
    self.stage = "policy"
    self.initiatorCookie = _newCookie()
    self.saBody = _saPayload(PROTO_ISAKMP, b"", [_ikeTransform(proposal) for proposal in self.proposals])
    vendors = [(PAYLOAD_VENDOR, vendor) for vendor in (VENDOR_NATT_RFC, *VENDOR_NATT_DRAFTS, VENDOR_DPD)]
    self._log(f"main mode: offering {len(self.proposals)} proposals to {self.serverIp}:{self.serverPort}")
    self._exchange(self._message(MAIN_MODE, 0, [(PAYLOAD_SA, self.saBody), *vendors]), self._onPolicy, "main mode message 1")
    self._exchange(self._keyMessage(), self._onKeys, "main mode message 3")
    self._exchange(self._authMessage(), self._onAuth, "main mode message 5")

  def _onPolicy(self, packet):
    if packet.exchange == INFORMATIONAL and not packet.encrypted:
      return self._checkNotifies(_decodePayloads(packet.body, packet.firstPayload))

    if packet.exchange != MAIN_MODE or packet.encrypted or packet.messageId or packet.responderCookie == ZERO_COOKIE:
      raise ValueError("not main mode message 2")

    payloads = _decodePayloads(packet.body, packet.firstPayload)

    if len(sas := [body for kind, body in payloads if kind == PAYLOAD_SA]) != 1:
      raise ValueError("main mode message 2 without one sa payload")

    if len(proposals := _decodeSa(sas[0])) != 1 or len(proposals[0][2]) != 1:
      raise ValueError("main mode message 2 without exactly one transform")

    transformId, pairs = proposals[0][2][0]

    if (chosen := self._matchIke(transformId, _firstOf(pairs))) is None:
      raise IkeError("server chose a phase 1 transform that was not offered")

    vendors = [body for kind, body in payloads if kind == PAYLOAD_VENDOR]
    self.natVersion = "rfc" if VENDOR_NATT_RFC in vendors else "draft" if any(v in vendors for v in VENDOR_NATT_DRAFTS) else None
    self.peerDpd = any(vendor[:14] == VENDOR_DPD[:14] for vendor in vendors)
    self.responderCookie, self.chosen = packet.responderCookie, chosen
    self.phase1Lifetime = _lifetimeOf(pairs, ATTR_LIFE_TYPE, ATTR_LIFE)
    natText = self.natVersion or "not offered"
    dpdText = "offered" if self.peerDpd else "not offered"
    self._log(
      f"server chose {chosen.cipher.upper()} / {chosen.hashName.upper()} / DH group {chosen.dhGroup}, lifetime {self.phase1Lifetime} s"
      f". NAT-T {natText}, DPD {dpdText}"
    )

    return True

  def _matchIke(self, transformId, values):
    return next((
      proposal for proposal in self.proposals
      if transformId == KEY_IKE and values.get(ATTR_AUTH) == AUTH_PSK and values.get(ATTR_GROUP) == proposal.dhGroup
      and (values.get(ATTR_CIPHER), values.get(ATTR_KEY_LENGTH, 0)) == IKE_CIPHERS[proposal.cipher]
      and values.get(ATTR_HASH) == IKE_HASHES[proposal.hashName]
    ), None)

  def _natHash(self, address, port):
    return _digest(self.chosen.hashName, self.initiatorCookie + self.responderCookie + socket.inet_aton(address) + pack(">H", port))

  def _keyMessage(self):
    self.stage = "keys"
    self.group = DH_GROUPS[self.chosen.dhGroup]
    self.private, self.publicKey = dhGenerate(self.group)
    self.nonce = token_bytes(NONCE_SIZE)
    payloads = [(PAYLOAD_KE, self.publicKey), (PAYLOAD_NONCE, self.nonce)]

    if self.natVersion:
      natd = NAT_PAYLOADS[self.natVersion][0]
      # rfc 3947 section 3.2 sends the peer's address first and our own after it. with a float socket our
      # hash deliberately uses port 0 so the server sees a nat and we float to its 4500 (spec: nat-t only)
      ownPort = 0 if self.floatSock is not None else self.localPort
      payloads += [(natd, self._natHash(self.serverIp, self.serverPort)), (natd, self._natHash(self.localIp, ownPort))]

    return self._message(MAIN_MODE, 0, payloads)

  def _onKeys(self, packet):
    if packet.exchange == INFORMATIONAL and not packet.encrypted:
      return self._checkNotifies(_decodePayloads(packet.body, packet.firstPayload))

    if packet.exchange != MAIN_MODE or packet.encrypted or packet.messageId:
      raise ValueError("not main mode message 4")

    payloads = _decodePayloads(packet.body, packet.firstPayload)
    values = _firstOf(payloads)

    if len(peerKey := values.get(PAYLOAD_KE, b"")) != self.group.size:
      raise ValueError("main mode message 4 without a valid key exchange")

    if not 8 <= len(peerNonce := values.get(PAYLOAD_NONCE, b"")) <= 256:
      raise ValueError("main mode message 4 without a valid nonce")

    self.shared = dhShared(self.group, self.private, peerKey)
    self.peerPublic, self.peerNonce = peerKey, peerNonce
    self._deriveKeys()

    if self.natVersion:
      self._checkNat([body for kind, body in payloads if kind == NAT_PAYLOADS[self.natVersion][0]])

      if self.floatSock is None:
        self._log("server offers NAT-T but no float socket was given. staying on the IKE port")

    self.floated = self.natVersion is not None and self.floatSock is not None

    return True

  def _deriveKeys(self):
    h, cookies = self.chosen.hashName, self.initiatorCookie + self.responderCookie
    self.skeyid = prf(h, self.psk, self.nonce + self.peerNonce)
    self.skeyidD = prf(h, self.skeyid, self.shared + cookies + b"\x00")
    self.skeyidA = prf(h, self.skeyid, self.skeyidD + self.shared + cookies + b"\x01")
    self.skeyidE = prf(h, self.skeyid, self.skeyidA + self.shared + cookies + b"\x02")
    self.cipher = self.chosen.cipher
    keySize, self.blockSize = CIPHERS[self.cipher]
    self.encKey = _expandKey(h, self.skeyidE, keySize)
    # appendix b: the first phase 1 iv is the hash of both public values
    self.iv = _digest(h, self.publicKey + self.peerPublic)[:self.blockSize]

  def _checkNat(self, hashes):
    if not hashes:
      return self._log("server sent no NAT-D payloads")

    behind = hashes[0] != self._natHash(self.localIp, self.localPort)
    serverBehind = self._natHash(self.serverIp, self.serverPort) not in hashes[1:]
    hostText = "a NAT in front of this host" if behind else "no NAT in front of this host"
    serverText = ", the server is behind a NAT" if serverBehind else ""
    self._log(f"NAT-D: {hostText}{serverText}")

  def _authMessage(self):
    self.stage = "auth"
    # protocol and port stay zero, which rfc 2407 section 4.6.2 allows and rfc 3947 section 4 asks for
    # id type 11 is a key id
    idType, idData = (11, self.ikeId.encode("utf-8")) if self.ikeId else (ID_IPV4_ADDR, socket.inet_aton(self.localIp))
    self.idBody = pack(">BBH", idType, 0, 0) + idData
    cookies = self.initiatorCookie + self.responderCookie
    hashI = prf(self.chosen.hashName, self.skeyid, self.publicKey + self.peerPublic + cookies + self.saBody + self.idBody)
    sealed, self.iv = self._encrypt(_encodePayloads([(PAYLOAD_ID, self.idBody), (PAYLOAD_HASH, hashI)]), self.iv)

    return _buildMessage(self.initiatorCookie, self.responderCookie, PAYLOAD_ID, MAIN_MODE, FLAG_ENCRYPTED, 0, sealed)

  def _onAuth(self, packet):
    if packet.exchange == INFORMATIONAL:
      payloads = self._openInformational(packet, self.iv) if packet.encrypted else _decodePayloads(packet.body, packet.firstPayload)

      return self._checkNotifies(payloads)

    if packet.exchange != MAIN_MODE or packet.messageId or not packet.encrypted:
      raise ValueError("not main mode message 6")

    # cookies travel in the clear, so a message 6 that does not decrypt or verify is dropped rather than
    # trusted as a verdict. if no valid one follows, the deadline reports the wrong psk (silenceError)
    try:
      plain, lastBlock = self._decrypt(packet.body, self.iv)
      values = _firstOf(_decodePayloads(plain, packet.firstPayload))
      idBody, hashR = values[PAYLOAD_ID], values[PAYLOAD_HASH]
    except Exception:
      raise ValueError("main mode message 6 did not decrypt, the pre-shared key may be wrong") from None

    material = self.peerPublic + self.publicKey + self.responderCookie + self.initiatorCookie + self.saBody + idBody

    if not hmac.compare_digest(prf(self.chosen.hashName, self.skeyid, material), hashR):
      raise ValueError("main mode message 6 failed its hash check, the pre-shared key may be wrong")

    self.phase1Iv = lastBlock
    self._log("main mode complete, server authenticated")

    return True

  # QUICK MODE -------------------------------------------------------------- #
  def _phase2Iv(self, messageId):
    # appendix b: hash of the last phase 1 cbc block and the message id
    return _digest(self.chosen.hashName, self.phase1Iv + pack(">I", messageId))[:self.blockSize]

  def _protectedMessage(self, exchange, messageId, payloads, iv):
    # hash(1) of quick mode and of informational exchanges covers the message id and every payload after it
    h = self.chosen.hashName
    size = hashlib.new(h).digest_size
    chain = _encodePayloads([(PAYLOAD_HASH, bytes(size)), *payloads])
    rest = chain[4 + size:]
    plain = chain[:4] + prf(h, self.skeyidA, pack(">I", messageId) + rest) + rest
    sealed, lastBlock = self._encrypt(plain, iv)

    return _buildMessage(self.initiatorCookie, self.responderCookie, PAYLOAD_HASH, exchange, FLAG_ENCRYPTED, messageId, sealed), lastBlock

  def _openHashed(self, packet, iv, prefix = b""):
    plain, lastBlock = self._decrypt(packet.body, iv)
    payloads = _decodePayloads(plain, packet.firstPayload)

    if not payloads or payloads[0][0] != PAYLOAD_HASH:
      raise ValueError("protected message does not open with a hash")

    rest = plain[4 + len(payloads[0][1]):_chainLength(payloads)]
    expected = prf(self.chosen.hashName, self.skeyidA, pack(">I", packet.messageId) + prefix + rest)

    if not hmac.compare_digest(expected, payloads[0][1]):
      raise ValueError("protected message failed its hash check")

    return payloads[1:], lastBlock

  def _openInformational(self, packet, base):
    if not packet.encrypted:
      raise ValueError("unprotected informational message")

    return self._openHashed(packet, _digest(self.chosen.hashName, base + pack(">I", packet.messageId))[:self.blockSize])[0]

  def _quickMode(self):
    self.stage = "quick"
    self.quickId = _newMessageId()
    # spi values 1 to 255 are reserved by rfc 4303
    self.inSpi = randbelow(0xFFFFFFFF - 0x100) + 0x100
    # udp-encapsulated-transport of rfc 3947 section 5.1 and of the drafts, plain transport is 2
    encapsulation = {"rfc": 4, "draft": 61444}[self.natVersion] if self.floated else 2
    pairs = list(dict.fromkeys([(self.chosen.cipher, self.chosen.hashName)] + [(p.cipher, p.hashName) for p in self.proposals]))
    self.espOffers = [(cipher, hashName, encapsulation) for cipher, hashName in pairs]
    sa = _saPayload(PROTO_ESP, pack(">I", self.inSpi), [_espTransform(*offer) for offer in self.espOffers])
    self.quickNonce = token_bytes(NONCE_SIZE)
    local, remote = socket.inet_aton(self.localIp), socket.inet_aton(self.serverIp)
    # l2tp traffic selectors: udp 1701 between the two addresses, which transport mode servers expect
    payloads = [(PAYLOAD_SA, sa), (PAYLOAD_NONCE, self.quickNonce), (PAYLOAD_ID, pack(">BBH", ID_IPV4_ADDR, UDP, L2TP_PORT) + local), (PAYLOAD_ID, pack(">BBH", ID_IPV4_ADDR, UDP, L2TP_PORT) + remote)]

    if self.floated:
      natOa = NAT_PAYLOADS[self.natVersion][1]
      payloads += [(natOa, pack(">BBH", ID_IPV4_ADDR, 0, 0) + local), (natOa, pack(">BBH", ID_IPV4_ADDR, 0, 0) + remote)]

    message, self.quickIv = self._protectedMessage(QUICK_MODE, self.quickId, payloads, self._phase2Iv(self.quickId))
    encapsulation = "UDP-encapsulated " if self.floated else ""
    self._log(f"quick mode: offering {len(self.espOffers)} ESP transforms, {encapsulation}transport mode")
    self._log(f"quick mode: IDci 17/1701 {self.localIp}, IDcr 17/1701 {self.serverIp}" + (f", NAT-OA initiator {self.localIp}, responder {self.serverIp}" if self.floated else ""))
    (cipher, hashName, _), outSpi, peerNonce, espLifetime = self._exchange(message, self._onQuickReply, "quick mode message 1")
    self._transmit(self.quickAck)
    self.peerQuickNonce, self.outSpi = peerNonce, outSpi
    channel = EspChannel(self._espSa(outSpi, cipher, hashName), self._espSa(self.inSpi, cipher, hashName))
    self.lifetime = min(self.phase1Lifetime, espLifetime)
    self.established, self.stage, self.establishedAt = True, "established", self.clock()
    self._log(f"quick mode complete: ESP {cipher.upper()} / {hashName.upper()}, lifetime {self.lifetime} s")

    return IkeResult(channel, self.lifetime, NAT_T_PORT if self.floated else self.serverPort, self.floatSock if self.floated else self.sock)

  def _onQuickReply(self, packet):
    if packet.exchange == INFORMATIONAL:
      return self._checkNotifies(self._openInformational(packet, self.phase1Iv))

    if packet.exchange != QUICK_MODE or packet.messageId != self.quickId or not packet.encrypted:
      raise ValueError("not the quick mode reply")

    payloads, lastBlock = self._openHashed(packet, self.quickIv, self.quickNonce)
    values = _firstOf(payloads)

    if not 8 <= len(peerNonce := values.get(PAYLOAD_NONCE, b"")) <= 256 or PAYLOAD_SA not in values:
      raise ValueError("quick mode reply without sa or nonce")

    proposals = _decodeSa(values[PAYLOAD_SA])

    if len(proposals) != 1 or proposals[0][0] != PROTO_ESP or len(proposals[0][1]) != 4 or len(proposals[0][2]) != 1:
      raise ValueError("quick mode reply without exactly one esp transform")

    transformId, pairs = proposals[0][2][0]
    attrs = _firstOf(pairs)
    offer = next((
      offer for offer in self.espOffers
      if (transformId, attrs.get(ESP_KEY_LENGTH, 0)) == ESP_CIPHERS[offer[0]] and attrs.get(ESP_AUTH) == ESP_AUTHS[offer[1]] and attrs.get(ESP_ENCAPSULATION) == offer[2]
    ), None)

    if offer is None:
      raise IkeError("server chose an ESP transform that was not offered")

    espLifetime = _lifetimeOf(pairs, ESP_LIFE_TYPE, ESP_LIFE)
    natOaKind = NAT_PAYLOADS[self.natVersion][1] if self.natVersion else None
    ids = ", ".join(_describeId(body) for kind, body in payloads if kind == PAYLOAD_ID) or "none"
    natOas = ", ".join(_describeId(body) for kind, body in payloads if kind == natOaKind) or "none"
    serverSpi = unpack(">I", proposals[0][1])[0]
    self._log(f"server quick mode reply: spi 0x{serverSpi:08x}, encapsulation {attrs.get(ESP_ENCAPSULATION)}, IDs {ids}, NAT-OA {natOas}")

    for kind, body in payloads:
      # 24576 is responder-lifetime
      if kind == PAYLOAD_NOTIFY and (parts := _notifyParts(body))[1] == 24576:
        espLifetime = min(espLifetime, _lifetimeOf(_decodeAttributes(parts[3]), ESP_LIFE_TYPE, ESP_LIFE))

    hash3 = prf(self.chosen.hashName, self.skeyidA, b"\x00" + pack(">I", self.quickId) + self.quickNonce + peerNonce)
    sealed, _ = self._encrypt(_encodePayloads([(PAYLOAD_HASH, hash3)]), lastBlock)
    self.quickAck = _buildMessage(self.initiatorCookie, self.responderCookie, PAYLOAD_HASH, QUICK_MODE, FLAG_ENCRYPTED, self.quickId, sealed)
    self.quickReplyRaw = packet.raw

    return offer, serverSpi, peerNonce, espLifetime

  def _espSa(self, spi, cipher, hashName):
    # rfc 2409 section 5.5: KEYMAT = prf(SKEYID_d, protocol | SPI | Ni_b | Nr_b), fed back until long enough
    # hmac keys as long as the digest (rfc 2404, rfc 4868) and the icv sizes they are cut to
    encSize, authSize = CIPHERS[cipher][0], {"sha1": 20, "sha256": 32}[hashName]
    seed = bytes([PROTO_ESP]) + pack(">I", spi) + self.quickNonce + self.peerQuickNonce
    material = block = b""

    while len(material) < encSize + authSize:
      block = prf(self.chosen.hashName, self.skeyidD, block + seed)
      material += block

    return EspSa(spi, cipher, material[:encSize], hashName, material[encSize:encSize + authSize], {"sha1": 12, "sha256": 16}[hashName])

  # AFTER NEGOTIATION ------------------------------------------------------- #
  def handle(self, packet):
    try:
      with self.lock:
        self._process(bytes(packet))
    except Exception as e:
      self._log(f"dropped a packet ({_describe(e)})")

  def _process(self, data):
    if not self.established:
      raise ValueError("no IKE SA yet")

    message = _parsePacket(data[len(NON_ESP_MARKER):] if isIke(data) else data)

    if (message.initiatorCookie, message.responderCookie) != (self.initiatorCookie, self.responderCookie):
      raise ValueError("cookies are not ours")

    if message.exchange == QUICK_MODE and message.raw == self.quickReplyRaw:
      self._log("quick mode reply repeated, sending the last message again")

      return self._transmit(self.quickAck)

    if message.exchange != INFORMATIONAL:
      raise ValueError("unexpected exchange type")

    payloads = self._openInformational(message, self.phase1Iv)
    self.dpdPendingSince = None

    for kind, body in payloads:
      if kind == PAYLOAD_NOTIFY:
        self._onNotify(body)
      elif kind == PAYLOAD_DELETE:
        self._onDelete(body)

  def _cookies(self):
    return self.initiatorCookie + self.responderCookie

  def _inform(self, kind, body):
    messageId = _newMessageId()
    self._transmit(self._protectedMessage(INFORMATIONAL, messageId, [(kind, body)], self._phase2Iv(messageId))[0])

  def _onNotify(self, body):
    protocol, code, spi, data = _notifyParts(body)

    if code not in (R_U_THERE, R_U_THERE_ACK):
      return self._log(f"server sent notify {NOTIFY_NAMES.get(code, code)}")

    if spi and spi != self._cookies() or len(data) != 4:
      raise ValueError("dpd notify for another IKE SA or without a sequence number")

    if code == R_U_THERE:
      self._inform(PAYLOAD_NOTIFY, _notifyBody(PROTO_ISAKMP, self._cookies(), R_U_THERE_ACK, data))
    elif unpack(">I", data)[0] != self.dpdSequence:
      self._log("DPD acknowledgement with an old sequence number")

  def _onDelete(self, body):
    if len(body) < 8 or len(body) < 8 + body[5] * (count := unpack(">H", body[6:8])[0]):
      raise ValueError("delete payload too short")

    protocol, size = body[4], body[5]
    spis = [body[8 + index * size:8 + (index + 1) * size] for index in range(count)]

    # rfc 2408 names the sender's own spi, but some servers name ours, so either ends the sa
    if protocol == PROTO_ISAKMP and self._cookies() in spis or protocol == PROTO_ESP and {pack(">I", self.outSpi), pack(">I", self.inSpi)} & set(spis):
      self.peerDeleted = True
      self._log("server deleted the security association")

  def sendDpd(self):
    try:
      with self.lock:
        if not self.established:
          return

        if not self.peerDpd:
          # a server without dpd never answers, so asking would only fake a dead peer
          if not self.dpdSkipLogged:
            self.dpdSkipLogged = True
            self._log("server does not support DPD, liveness checks skipped")
          return

        self.dpdSequence = (self.dpdSequence + 1) & 0xFFFFFFFF
        self.lastDpdSent = self.clock()

        if self.dpdPendingSince is None:
          self.dpdPendingSince = self.lastDpdSent

        self._inform(PAYLOAD_NOTIFY, _notifyBody(PROTO_ISAKMP, self._cookies(), R_U_THERE, pack(">I", self.dpdSequence)))
    except Exception as e:
      self._log(f"DPD send failed ({_describe(e)})")

  def dpdAlive(self, now):
    # false once an r-u-there has gone unanswered, with nothing else heard either, for longer than dpdTimeout
    return self.dpdPendingSince is None or now - self.dpdPendingSince <= self.dpdTimeout

  def needsRekey(self, now):
    # rekeying is not implemented. the tunnel only warns when this turns true
    # rekey at 80% of the lifetime
    return self.established and self.lifetime > 0 and now - self.establishedAt >= 0.8 * self.lifetime

  def delete(self):
    try:
      with self.lock:
        if not self.established:
          return

        self._inform(PAYLOAD_DELETE, pack(">IBBH", DOI_IPSEC, PROTO_ESP, 4, 1) + pack(">I", self.inSpi))
        self._inform(PAYLOAD_DELETE, pack(">IBBH", DOI_IPSEC, PROTO_ISAKMP, 16, 1) + self._cookies())
        self.established = False
        self._log("sent delete for the IPsec and IKE security associations")
    except Exception as e:
      self._log(f"delete failed ({_describe(e)})")
# ---------------------------------------------------------------------------- #
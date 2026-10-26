# ---------------------------------------------------------------------------- #
# DESCRIPTION: socket-free ppp client (LCP, PAP, CHAP, MS-CHAPv2, IPCP, CCP/MPPE)
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import hashlib
import hmac
import re

from secrets import randbelow, token_bytes

from modules.crypto import SALT_40, SHS_PAD1, SHS_PAD2, MppeStream, authenticatorResponse, mppeKeys, mppeStartKeys, ntResponse, sha1
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
PROTO_LCP = 0xC021
PROTO_PAP = 0xC023
PROTO_CHAP = 0xC223
PROTO_IPCP = 0x8021
PROTO_CCP = 0x80FD
PROTO_IP = 0x0021
PROTO_MPPE = 0x00FD

CONF_REQ, CONF_ACK, CONF_NAK, CONF_REJ, TERM_REQ, TERM_ACK, CODE_REJ, PROTO_REJ, ECHO_REQ = range(1, 10)
RESET_REQ, RESET_ACK = 14, 15
CODE_NAMES = {CONF_ACK: "configure-ack", CONF_NAK: "configure-nak", CONF_REJ: "configure-reject"}

RESTART_INTERVAL = 3.0
MAX_CONFIGURE = 10
MAX_AUTH_NAKS = 5
CCOUNT_SPACE = 0x1000

MPPE_OPTION = 18
MPPE_STATELESS = 0x01000000
# rfc 3078 supported bits: S (0x40) is 128-bit, M (0x80) is 56-bit, L (0x20) is 40-bit. strongest first
MPPE_STRENGTHS = {0x40: (16, 128), 0x80: (8, 56), 0x20: (8, 40)}

# rfc 1877 primary and secondary dns are options 0x81 and 0x83, the same numbers microsoft uses
IPCP_ADDRESS, IPCP_DNS1, IPCP_DNS2 = 3, 129, 131

LCP_LENGTHS = {1: 2, 2: 4, 5: 4, 7: 0, 8: 0}
AUTH_OPTIONS = {
  "mschapv2": PROTO_CHAP.to_bytes(2, "big") + b"\x81",
  "chap": PROTO_CHAP.to_bytes(2, "big") + b"\x05",
  "pap": PROTO_PAP.to_bytes(2, "big")
}
UNKNOWN_USER = re.compile(r"(unknown|no such)\s+(user|account)|(user|account)\S*\s+(unknown|not found|does not exist)", re.I)

class PppError(Exception):
  pass

def _encodeFrame(protocol, payload):
  # l2tp strips hdlc flags and fcs, yet peers expect FF 03 and an uncompressed 2-byte protocol
  return b"\xff\x03" + protocol.to_bytes(2, "big") + payload

def _decodeFrame(frame):
  if len(frame) < 2:
    raise PppError("frame shorter than two bytes")

  body = frame[2:] if frame[:2] == b"\xff\x03" else frame

  # an odd first octet marks a protocol field compressed to one byte (rfc 1661 section 2)
  if body[:1] and body[0] & 1:
    return body[0], body[1:]

  if len(body) < 2:
    raise PppError("frame has no protocol field")

  return int.from_bytes(body[:2], "big"), body[2:]

def _controlPacket(code, ident, data = b""):
  return bytes([code, ident]) + (len(data) + 4).to_bytes(2, "big") + data

def _splitPacket(payload, name):
  length = int.from_bytes(payload[2:4], "big") if len(payload) >= 4 else 0

  if not 4 <= length <= len(payload):
    raise PppError(f"{name} packet with a bad length")

  return payload[0], payload[1], payload[4:length]

def _encodeOptions(options):
  return b"".join(bytes([kind, len(value) + 2]) + value for kind, value in options)

def _parseOptions(data):
  options, offset = [], 0

  while offset < len(data):
    if len(data) - offset < 2 or not 2 <= data[offset + 1] <= len(data) - offset:
      raise PppError("option with a bad length")

    options.append((data[offset], bytes(data[offset + 2:offset + data[offset + 1]])))
    offset += data[offset + 1]

  return options

def _ipText(value):
  return ".".join(str(part) for part in value)

def _cleanText(raw, secret):
  # scrub an echoed password before and after normalising, and only then cut, so no part of it survives
  normalize = lambda text: " ".join("".join(c if c.isprintable() else " " for c in text).split())
  decoded = raw.decode("utf-8", errors = "replace")
  text = normalize(decoded.replace(secret, "***") if secret else decoded)

  return (text.replace(normalize(secret), "***") if normalize(secret) else text)[:200]

def _mppeChoice(bits):
  # pick the strongest offered key length and keep stateless mode when the peer offers it
  strength = next((flag for flag in MPPE_STRENGTHS if bits & flag), 0)

  return strength and strength | (bits & MPPE_STATELESS)

class MppeChannel:
  # one direction of an mppe link. key changes follow rfc 3078 section 7
  def __init__(self, startKey, sessionKey, strength, stateless):
    self.startKey, self.sessionKey, self.strength, self.stateless = startKey, sessionKey, strength, stateless
    self.stream = MppeStream(sessionKey)
    self.ccount = CCOUNT_SPACE - 1
    self.flushNext, self.discarding, self.resetWanted = True, False, False

  def rekey(self):
    interim = sha1(self.startKey + SHS_PAD1 + self.sessionKey + SHS_PAD2)[:len(self.startKey)]
    key = MppeStream(interim).encrypt(interim)
    self.sessionKey = SALT_40 + key[3:] if self.strength == 40 else SALT_40[:1] + key[1:] if self.strength == 56 else key
    self.stream = MppeStream(self.sessionKey)

  def encrypt(self, data):
    self.ccount = (self.ccount + 1) % CCOUNT_SPACE
    flag = self.stateless or (self.ccount & 0xff) == 0xff

    if flag:
      self.rekey()
    elif self.flushNext:
      self.stream = MppeStream(self.sessionKey)

    header = (0x9000 if flag or self.flushNext else 0x1000) | self.ccount
    self.flushNext = False

    return header.to_bytes(2, "big") + self.stream.encrypt(data)

  def decrypt(self, payload):
    header = int.from_bytes(payload[:2], "big")
    ccount, flushed = header & 0xfff, header & 0x8000
    steps = (ccount - self.ccount) % CCOUNT_SPACE

    # a zero or backward step is a duplicate or a late packet
    if len(payload) < 3 or not header & 0x1000 or not 0 < steps < CCOUNT_SPACE // 2:
      return None

    if self.stateless:
      for _ in range(steps):
        self.rekey()
    elif steps != 1 and not flushed:
      # a stateful gap: drop until the peer flushes after our reset-request
      self.resetWanted, self.discarding = not self.discarding, True

      return None
    else:
      for step in range(1, steps + 1):
        if ((self.ccount + step) & 0xff) == 0xff:
          self.rekey()

      if flushed and (ccount & 0xff) != 0xff:
        self.stream = MppeStream(self.sessionKey)

      self.discarding = False

    self.ccount = ccount

    return self.stream.decrypt(payload[2:])

class ControlProtocol:
  # negotiation state of one rfc 1661 option automaton (lcp, ipcp or ccp)
  def __init__(self, name, protocol, options):
    self.name, self.protocol, self.options = name, protocol, options
    self.ident, self.naks = 0, 0
    self.ourAcked = self.peerAcked = self.opened = False
    self.peerAgreed = {}

class PppSession:
  state = property(lambda self: self._state)
  localIp = property(lambda self: self._localIp)
  dnsServers = property(lambda self: list(self._dnsServers))
  authName = property(lambda self: self._authName)
  mppeActive = property(lambda self: self._mppeActive)
  failReason = property(lambda self: self._failReason)
  failField = property(lambda self: self._failField)

  def __init__(self, username, password, authMethods, mppe, mru, send, onLog):
    self.username, self._password = username, password
    self.authMethods = [method for method in authMethods if method in AUTH_OPTIONS]
    self.mppe, self.mru, self.send, self.onLog = mppe, mru, send, onLog
    self.timers, self.now, self.lastIdent = {}, None, 0
    self._state, self._failReason, self._failField = "lcp", "", None
    self._resetLink()

  def _resetLink(self):
    self.magic = (randbelow(0xFFFFFFFE) + 1).to_bytes(4, "big")
    self.lcp = ControlProtocol("lcp", PROTO_LCP, {1: self.mru.to_bytes(2, "big"), 5: self.magic})
    self.ipcp = ControlProtocol("ipcp", PROTO_IPCP, {kind: bytes(4) for kind in (IPCP_ADDRESS, IPCP_DNS1, IPCP_DNS2)})
    self.ccp = ControlProtocol("ccp", PROTO_CCP, {MPPE_OPTION: (MPPE_STATELESS | 0x40).to_bytes(4, "big")})
    self.timers.clear()
    self.authMethod, self.authNaks, self.chapAnswer, self.papIdent = None, 0, None, None
    self.authChallenge = self.peerChallenge = self.ntResp = None
    self.ccpStatus, self.txChannel, self.rxChannel = "off", None, None
    self._localIp, self._dnsServers, self._authName, self._mppeActive = "", [], "", False

  def _log(self, message):
    self.onLog(f"PPP {message}")

  def _newIdent(self):
    self.lastIdent = (self.lastIdent + 1) % 256

    return self.lastIdent

  def _emit(self, protocol, code, ident, data = b""):
    self.send(_encodeFrame(protocol, _controlPacket(code, ident, data)))

  def _arm(self, key, frame):
    # frame None waits for the peer without retransmitting (a chap challenge or verdict)
    self.timers[key] = [frame, 1, None if self.now is None else self.now + RESTART_INTERVAL]

    if frame:
      self.send(frame)

  def start(self):
    self._log("starting LCP negotiation")
    self._sendRequest(self.lcp)

  def close(self):
    if self._state not in ("closed", "failed") and self.lcp.opened:
      self._emit(PROTO_LCP, TERM_REQ, self._newIdent())

    self.timers.clear()
    self._state = "failed" if self._state == "failed" else "closed"

  def _fail(self, reason, field = None):
    if self._state in ("failed", "closed"):
      return

    self._state, self._failReason, self._failField = "failed", reason, field
    self.timers.clear()
    self._log(f"failed: {reason}")

  def tick(self, now):
    try:
      self.now = now

      for key, timer in list(self.timers.items()):
        frame, tries, deadline = timer

        if key not in self.timers:
          continue

        if deadline is None:
          timer[2] = now + RESTART_INTERVAL
        elif now >= deadline and tries >= MAX_CONFIGURE:
          self._timedOut(key)
        elif now >= deadline:
          timer[1:] = [tries + 1, now + RESTART_INTERVAL]

          if frame:
            self._log(f"{key.upper()} retransmission {tries + 1}")
            self.send(frame)
    except Exception as e:
      self._log(f"timer error ({type(e).__name__})")

  def _timedOut(self, key):
    frame = self.timers.pop(key)[0]
    waiting = frame is None and key in ("lcp", "ipcp", "ccp")
    reason = f"server never sent its own {key.upper()} request" if waiting else f"{key.upper()} got no answer from the server"

    if key == "ccp":
      return self._ccpDown(reason)

    self._fail(f"{reason} after {MAX_CONFIGURE * RESTART_INTERVAL:.0f} s" if waiting else f"{reason} after {MAX_CONFIGURE} attempts")

  def receive(self, frame):
    try:
      if len(frame) > 65535:
        raise PppError("oversized frame")

      protocol, payload = _decodeFrame(bytes(frame))

      return self._dispatch(protocol, payload)
    except Exception as e:
      self._log(f"dropped frame ({e if isinstance(e, PppError) else type(e).__name__})")

  def _dispatch(self, protocol, payload):
    if self._state in ("failed", "closed"):
      if protocol == PROTO_LCP and payload[:1] == bytes([TERM_REQ]) and len(payload) > 1:
        self._emit(PROTO_LCP, TERM_ACK, payload[1])

      return None

    if protocol == PROTO_LCP:
      self._handleControl(self.lcp, payload)
    elif not self.lcp.opened:
      self._log(f"ignored protocol 0x{protocol:04x} before LCP is open")
    elif protocol == PROTO_PAP:
      self._handlePap(payload)
    elif protocol == PROTO_CHAP:
      self._handleChap(payload)
    elif protocol in (PROTO_IPCP, PROTO_CCP) and self._state in ("lcp", "auth"):
      self._log(f"ignored protocol 0x{protocol:04x} before authentication ends")
    elif protocol == PROTO_CCP and not self._canMppe():
      self._protocolReject(protocol, payload)
    elif protocol in (PROTO_IPCP, PROTO_CCP):
      self._handleControl(self.ipcp if protocol == PROTO_IPCP else self.ccp, payload)
    elif protocol == PROTO_IP:
      return payload if self._state == "up" and not self._mppeActive else None
    elif protocol == PROTO_MPPE:
      return self._inboundMppe(payload)
    else:
      self._protocolReject(protocol, payload)

    return None

  def _protocolReject(self, protocol, payload):
    self._log(f"rejected protocol 0x{protocol:04x}")
    self._emit(PROTO_LCP, PROTO_REJ, self._newIdent(), protocol.to_bytes(2, "big") + payload[:max(0, self.mru - 10)])

  def _handleControl(self, cp, payload):
    code, ident, data = _splitPacket(payload, cp.name)

    if code == CONF_REQ:
      self._answerRequest(cp, ident, data)
    elif code in (CONF_ACK, CONF_NAK, CONF_REJ):
      self._answerReply(cp, code, ident, data)
    elif code == TERM_REQ:
      self._emit(cp.protocol, TERM_ACK, ident)
      self._ccpDown("server closed CCP") if cp is self.ccp else self._fail(f"server closed the {cp.name.upper()} layer")
    elif code in (TERM_ACK, CODE_REJ):
      self._log(f"{cp.name.upper()} code {code} from the server")
    elif cp is self.lcp and PROTO_REJ <= code <= 13:
      self._handleLcpExtra(code, ident, data)
    elif cp is self.ccp and code == RESET_REQ:
      # rfc 1962 wants a reset-ack for every reset-request, even before any mppe channel exists
      if self.txChannel:
        self.txChannel.flushNext = True

      self._emit(PROTO_CCP, RESET_ACK, ident)
    elif cp is self.ccp and code == RESET_ACK:
      self._log("CCP reset acknowledged")
    else:
      self._emit(cp.protocol, CODE_REJ, self._newIdent(), payload[:max(4, self.mru - 8)])

  def _handleLcpExtra(self, code, ident, data):
    if code == PROTO_REJ and len(data) >= 2:
      rejected = int.from_bytes(data[:2], "big")
      self._log(f"server rejected protocol 0x{rejected:04x}")

      if rejected == PROTO_CCP and self.ccpStatus != "rejected":
        self._ccpDown("server does not speak CCP")
      elif rejected in (PROTO_IPCP, PROTO_PAP, PROTO_CHAP):
        self._fail(f"server rejected protocol 0x{rejected:04x}")
    elif code == ECHO_REQ and self.lcp.opened:
      self._emit(PROTO_LCP, ECHO_REQ + 1, ident, self.magic + data[4:])

  def _sendRequest(self, cp):
    cp.ident = self._newIdent()
    self._arm(cp.name, _encodeFrame(cp.protocol, _controlPacket(CONF_REQ, cp.ident, _encodeOptions(cp.options.items()))))

  def _answerRequest(self, cp, ident, data):
    options = _parseOptions(data)

    if cp is self.lcp and cp.opened:
      self._log("LCP renegotiation started by the server")
      self._resetLink()
      self._state = "lcp"
      self._sendRequest(self.lcp)
      cp = self.lcp

    verdicts = {CONF_ACK: [], CONF_NAK: [], CONF_REJ: []}

    for kind, value in options:
      verdict, reply = self._judge(cp, kind, value)
      verdicts[verdict].append((kind, reply))

    code = CONF_REJ if verdicts[CONF_REJ] else CONF_NAK if verdicts[CONF_NAK] else CONF_ACK
    self._emit(cp.protocol, code, ident, data if code == CONF_ACK else _encodeOptions(verdicts[code]))
    self._log(f"{cp.name.upper()} answered the server request with {CODE_NAMES[code]}")
    cp.peerAcked = code == CONF_ACK

    if cp.peerAcked:
      cp.peerAgreed = dict(options)
      self._checkOpened(cp)

      if cp.ourAcked:
        self.timers.pop(cp.name, None)

  def _judge(self, cp, kind, value):
    if cp is self.lcp and LCP_LENGTHS.get(kind) == len(value):
      return CONF_ACK, value

    if cp is self.lcp and kind == 3:
      proposed = next((name for name, option in AUTH_OPTIONS.items() if option == value), None)
      listed = proposed in self.authMethods
      rank = self.authMethods.index(proposed) if listed else len(self.authMethods)

      # settle for a listed but less preferred method once the nak budget is spent
      if listed and (rank == 0 or self.authNaks >= MAX_AUTH_NAKS):
        return CONF_ACK, value

      if rank and self.authNaks < MAX_AUTH_NAKS:
        # suggest the better listed methods in turn so a peer that cannot do one gets the next
        self.authNaks += 1

        return CONF_NAK, AUTH_OPTIONS[self.authMethods[(self.authNaks - 1) % rank]]

    if cp is self.ipcp and kind == IPCP_ADDRESS and len(value) == 4 and any(value):
      return CONF_ACK, value

    if cp is self.ccp and kind == MPPE_OPTION and len(value) == 4:
      bits = int.from_bytes(value, "big")

      if choice := _mppeChoice(bits):
        return CONF_ACK if choice == bits else CONF_NAK, choice.to_bytes(4, "big")

    return CONF_REJ, value

  def _answerReply(self, cp, code, ident, data):
    if ident != cp.ident or cp.ourAcked or (cp is self.ccp and self.ccpStatus != "negotiating"):
      return self._log(f"{cp.name.upper()} ignored a stale reply")

    if code == CONF_ACK:
      cp.ourAcked = True

      # keep a bounded wait for the server's own request so a silent server cannot stall the link
      if cp.peerAcked:
        self.timers.pop(cp.name, None)
      else:
        self._arm(cp.name, None)

      return self._checkOpened(cp)

    cp.naks += 1

    if cp.naks > MAX_CONFIGURE:
      return self._fail(f"{cp.name.upper()} negotiation did not converge")

    for kind, value in _parseOptions(data):
      if kind in cp.options:
        self._adjust(cp, code, kind, value)

    if self._state != "failed" and (cp is not self.ccp or self.ccpStatus == "negotiating"):
      self._log(f"{cp.name.upper()} request adjusted after {CODE_NAMES[code]}")
      self._sendRequest(cp)

  def _adjust(self, cp, code, kind, value):
    if cp is self.ccp:
      choice = _mppeChoice(int.from_bytes(value, "big")) if code == CONF_NAK and len(value) == 4 else 0

      if not choice:
        return self._ccpDown("server refused the MPPE option")

      cp.options[kind] = choice.to_bytes(4, "big")
    elif code == CONF_REJ and cp is self.ipcp and kind == IPCP_ADDRESS:
      self._fail("server refused to assign an address")
    elif code == CONF_REJ or (cp is self.ipcp and kind != IPCP_ADDRESS and len(value) == 4 and not any(value)):
      del cp.options[kind]
    elif cp is self.ipcp and len(value) == 4:
      cp.options[kind] = value
    elif kind == 1 and len(value) == 2 and int.from_bytes(value, "big") >= 128:
      cp.options[kind] = value
    elif kind == 5:
      self.magic = cp.options[kind] = (randbelow(0xFFFFFFFE) + 1).to_bytes(4, "big")

  def _checkOpened(self, cp):
    if not (cp.ourAcked and cp.peerAcked) or cp.opened:
      return

    cp.opened = True
    self._log(f"{cp.name.upper()} opened")

    if cp is self.lcp:
      self._beginAuth()
    elif cp is self.ccp:
      self._startMppe()
    else:
      self._maybeUp()

  def _beginAuth(self):
    agreed = self.lcp.peerAgreed.get(3)
    self.authMethod = next((name for name, option in AUTH_OPTIONS.items() if option == agreed), None)

    if not self.authMethod:
      self._log("server asked for no authentication")

      return self._beginNetwork()

    self._state, self._authName = "auth", {"mschapv2": "MS-CHAPv2", "chap": "CHAP", "pap": "PAP"}[self.authMethod]
    self._log(f"authenticating with {self._authName}")

    if self.authMethod != "pap":
      return self._arm("chap", None)

    user, secret = self.username.encode(), self._password.encode()

    if len(user) > 255 or len(secret) > 255:
      return self._fail("username or password is too long for PAP")

    self.papIdent = self._newIdent()
    self._arm("pap", _encodeFrame(PROTO_PAP, _controlPacket(1, self.papIdent, bytes([len(user)]) + user + bytes([len(secret)]) + secret)))

  def _handlePap(self, payload):
    code, ident, data = _splitPacket(payload, "pap")

    if self._state != "auth" or self.authMethod != "pap" or ident != self.papIdent or code not in (2, 3):
      return self._log("PAP ignored an unexpected packet")

    self.timers.pop("pap", None)
    message = data[1:1 + data[0]] if data else b""
    self._authSucceeded() if code == 2 else self._authRejected(message)

  def _handleChap(self, payload):
    code, ident, data = _splitPacket(payload, "chap")

    if self.authMethod not in ("chap", "mschapv2"):
      return self._log("CHAP ignored a packet for an authentication it did not agree")

    if code == 1:
      if not data or len(data) < 1 + data[0]:
        raise PppError("chap challenge with a bad value size")

      return self._answerChallenge(ident, data[1:1 + data[0]])

    if self._state != "auth" or not self.chapAnswer or ident != self.chapAnswer[0] or code not in (3, 4):
      return self._log("CHAP ignored a stale packet")

    self.timers.pop("chap", None)
    self._chapSuccess(data) if code == 3 else self._authRejected(data)

  def _answerChallenge(self, ident, challenge):
    # a repeated challenge means our response got lost, so resend it unchanged
    if self.chapAnswer and self.chapAnswer[:2] == (ident, challenge):
      return self.send(self.chapAnswer[2])

    if self.authMethod == "mschapv2":
      if len(challenge) != 16:
        raise PppError("ms-chapv2 challenge is not 16 bytes")

      # rfc 2759 hashes the user name without any domain prefix
      peerChallenge = token_bytes(16)
      ntResp = ntResponse(challenge, peerChallenge, self.username.split("\\")[-1], self._password)
      value = peerChallenge + bytes(8) + ntResp + b"\x00"

      # a re-challenge after authentication must not move the mppe keys under a running link
      if self._state == "auth":
        self.authChallenge, self.peerChallenge, self.ntResp = challenge, peerChallenge, ntResp
    else:
      value = hashlib.md5(bytes([ident]) + self._password.encode() + challenge).digest()

    frame = _encodeFrame(PROTO_CHAP, _controlPacket(2, ident, bytes([len(value)]) + value + self.username.encode()))
    self.chapAnswer = (ident, challenge, frame)
    self._log(f"answered the {self._authName} challenge")

    if self._state == "auth":
      self._arm("chap", None)

    self.send(frame)

  def _chapSuccess(self, data):
    if self.authMethod == "mschapv2":
      found = re.search(r"S=([0-9A-Fa-f]{40})", data.decode("latin-1"))
      user = self.username.split("\\")[-1]
      expected = authenticatorResponse(self._password, self.ntResp, self.peerChallenge, self.authChallenge, user)

      if not found or not hmac.compare_digest("S=" + found.group(1).upper(), expected):
        return self._fail("server failed MS-CHAPv2 mutual authentication (bad authenticator response)")

    self._authSucceeded()

  def _authSucceeded(self):
    self._log(f"{self._authName} authentication accepted")
    self._beginNetwork()

  def _authRejected(self, message):
    text = _cleanText(message, self._password)
    code = int(found.group(1)) if (found := re.search(r"\bE=(\d+)", text)) else None
    detail = (found.group(1).strip() if (found := re.search(r"\bM=(.*)$", text)) else "" if code else text) or "no message"
    # 646 logon hours, 647 account disabled, 649 no dial-in permission are account problems, not password ones
    field = "username" if code in (646, 647, 649) or UNKNOWN_USER.search(detail) else "password"
    errorText = f" (error {code})" if code else ""
    self._fail(f"{self._authName} authentication rejected{errorText}: {detail}", field)

  def _beginNetwork(self):
    self._state = "ipcp"

    if self.mppe != "off" and self.authMethod == "mschapv2":
      self.ccpStatus = "negotiating"
      self._sendRequest(self.ccp)
    elif self.mppe == "required":
      return self._fail("server did not agree to MPPE")

    self._sendRequest(self.ipcp)

  def _canMppe(self):
    return self.mppe != "off" and self.authMethod == "mschapv2" and self.ccpStatus != "rejected"

  def _ccpDown(self, reason):
    self.timers.pop("ccp", None)
    self.timers.pop("mppe reset", None)
    self.ccpStatus, self.txChannel, self.rxChannel, self._mppeActive = "rejected", None, None, False
    self._log(f"MPPE negotiation ended: {reason}")

    if self.mppe == "required":
      return self._fail("server did not agree to MPPE")

    self._maybeUp()

  def _mppeChannel(self, bits, direction):
    keyLength, strength = MPPE_STRENGTHS[bits & 0xff]
    sessionKey = mppeKeys(self._password, self.ntResp, keyLength, strength)[direction]
    startKey = mppeStartKeys(self._password, self.ntResp, keyLength)[direction]

    return MppeChannel(startKey, sessionKey, strength, bool(bits & MPPE_STATELESS))

  def _startMppe(self):
    # a ccp request names what its sender receives: ours sets inbound, the server's sets outbound
    receiveBits = int.from_bytes(self.ccp.options[MPPE_OPTION], "big")
    sendBits = int.from_bytes(self.ccp.peerAgreed.get(MPPE_OPTION, bytes(4)), "big")

    if not _mppeChoice(sendBits):
      return self._ccpDown("server CCP request carried no MPPE")

    self.txChannel, self.rxChannel = self._mppeChannel(sendBits, 0), self._mppeChannel(receiveBits, 1)
    self.ccpStatus, self._mppeActive = "open", True
    mode = lambda bits: f"{MPPE_STRENGTHS[bits & 0xff][1]}-bit " + ("stateless" if bits & MPPE_STATELESS else "stateful")
    self._log(f"MPPE on, send {mode(sendBits)}, receive {mode(receiveBits)}")
    self._maybeUp()

  def _maybeUp(self):
    if self._state != "ipcp" or not self.ipcp.opened or self.ccpStatus == "negotiating":
      return

    address = self.ipcp.options[IPCP_ADDRESS]

    if not any(address):
      return self._fail("server did not assign an address")

    self._localIp = _ipText(address)
    self._dnsServers = [_ipText(value) for kind, value in self.ipcp.options.items() if kind != IPCP_ADDRESS and any(value)]
    self._state = "up"
    dnsText = ", ".join(self._dnsServers) or "none"
    self._log(f"link up, local address {self._localIp}, dns {dnsText}")

  def _inboundMppe(self, payload):
    if not self.rxChannel or self._state != "up":
      return self._log("dropped an MPPE packet outside an MPPE session")

    plain = self.rxChannel.decrypt(payload)

    # retransmit the reset-request until a flushed packet ends the discard state
    if self.rxChannel.resetWanted:
      self.rxChannel.resetWanted = False
      self._arm("mppe reset", _encodeFrame(PROTO_CCP, _controlPacket(RESET_REQ, self._newIdent())))
    elif not self.rxChannel.discarding:
      self.timers.pop("mppe reset", None)

    if plain is None:
      return self._log("dropped an MPPE packet out of sequence")

    protocol, data = _decodeFrame(plain)

    return data if protocol == PROTO_IP else None

  def sendIp(self, packet):
    if self._state != "up":
      return

    if self.txChannel:
      return self.send(_encodeFrame(PROTO_MPPE, self.txChannel.encrypt(PROTO_IP.to_bytes(2, "big") + packet)))

    self.send(_encodeFrame(PROTO_IP, packet))
# ---------------------------------------------------------------------------- #
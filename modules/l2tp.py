# ---------------------------------------------------------------------------- #
# DESCRIPTION: socket-free l2tpv2 client (rfc 2661) with a reliable control channel
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
from secrets import randbelow
from struct import pack
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
SCCRQ, SCCRP, SCCCN, STOPCCN, HELLO = 1, 2, 3, 4, 6
ICRQ, ICRP, ICCN, CDN = 10, 11, 12, 14
MESSAGE_NAMES = {SCCRQ: "SCCRQ", SCCRP: "SCCRP", SCCCN: "SCCCN", STOPCCN: "StopCCN", HELLO: "HELLO", ICRQ: "ICRQ", ICRP: "ICRP", ICCN: "ICCN", CDN: "CDN"}

AVP_MESSAGE_TYPE, AVP_RESULT, AVP_VERSION, AVP_FRAMING_CAPS, AVP_HOST_NAME = 0, 1, 2, 3, 7
AVP_TUNNEL_ID, AVP_WINDOW, AVP_SESSION_ID, AVP_SERIAL, AVP_BEARER_TYPE = 9, 10, 14, 15, 18
AVP_FRAMING_TYPE, AVP_TX_SPEED = 19, 24

FRAMING_SYNC = 2

# every m-bit avp of rfc 2661 section 4.4 is accepted and ignored except challenge (11), challenge response (13)
# and random vector (36), which need a tunnel secret we do not have
KNOWN_AVPS = (0, 1, 2, 3, 4, 7, 9, 10, 12, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 34, 35, 39)

ACTIVE_STATES = ("tunnel", "session", "up")
HEADER_LENGTH = 12

class L2tpError(Exception):
  pass

def _newId():
  return randbelow(0xFFFF) + 1

def _avp(kind, value):
  # every avp we send is mandatory, which rfc 2661 requires for all of them
  return pack(">HHH", 0x8000 | (6 + len(value)), 0, kind) + value

def _messageAvps(messageType, *others):
  return _avp(AVP_MESSAGE_TYPE, pack(">H", messageType)) + b"".join(others)

def _number(kind, value, size = 4):
  return _avp(kind, value.to_bytes(size, "big"))

def _buildControl(tunnelId, sessionId, ns, nr, avps = b""):
  # 0xC802 is a control message with length and sequence bits, version 2
  return pack(">HHHHHH", 0xC802, HEADER_LENGTH + len(avps), tunnelId, sessionId, ns, nr) + avps

def _parseHeader(data):
  if len(data) < 6:
    raise L2tpError("datagram shorter than an l2tp header")

  flags = data[0]
  control, hasLength, hasSequence, hasOffset = flags & 0x80, flags & 0x40, flags & 0x08, flags & 0x02

  if data[1] & 0x0F != 2:
    raise L2tpError("unsupported l2tp version")

  if control and not (hasLength and hasSequence) or control and hasOffset:
    raise L2tpError("control message with a bad header")

  start = 4 if hasLength else 2

  if hasLength:
    if not 6 <= (length := int.from_bytes(data[2:4], "big")) <= len(data):
      raise L2tpError("length does not fit the datagram")

    data = data[:length]

  position = start + 4 + (4 if hasSequence else 0)

  if len(data) < position:
    raise L2tpError("header runs past the datagram")

  tunnel, session = int.from_bytes(data[start:start + 2], "big"), int.from_bytes(data[start + 2:start + 4], "big")
  ns, nr = (int.from_bytes(data[start + 4:start + 6], "big"), int.from_bytes(data[start + 6:start + 8], "big")) if hasSequence else (0, 0)

  if hasOffset:
    if len(data) < position + 2 or (position := position + 2 + int.from_bytes(data[position:position + 2], "big")) > len(data):
      raise L2tpError("offset runs past the datagram")

  return bool(control), tunnel, session, ns, nr, data[position:]

def _parseAvps(body):
  avps, offset = [], 0

  while offset < len(body):
    if len(body) - offset < 6 or not 6 <= (length := int.from_bytes(body[offset:offset + 2], "big") & 0x03FF) <= len(body) - offset:
      raise L2tpError("avp with a bad length")

    flags = int.from_bytes(body[offset:offset + 2], "big")
    vendor, kind = int.from_bytes(body[offset + 2:offset + 4], "big"), int.from_bytes(body[offset + 4:offset + 6], "big")
    avps.append((bool(flags & 0x8000), bool(flags & 0x4000), vendor, kind, bytes(body[offset + 6:offset + length])))
    offset += length

  return avps

def _resultText(value):
  # result code, optional error code and optional text. decode defensively since the peer is a stranger
  if not value or len(value) < 2:
    return ""

  result = int.from_bytes(value[:2], "big")
  text = f"result {result}"

  if len(value) >= 4:
    error = int.from_bytes(value[2:4], "big")
    text += f", error {error}"

  message = " ".join("".join(c if c.isprintable() else " " for c in value[4:].decode("utf-8", errors = "replace")).split())[:200]

  return f" ({text}: {message})" if message else f" ({text})"

class L2tpTunnel:
  state = property(lambda self: self._state)
  failReason = property(lambda self: self._failReason)

  def __init__(self, send, hostName, helloInterval, onLog):
    self.send, self.hostName, self.helloInterval, self.onLog = send, hostName, helloInterval, onLog
    self._state, self._failReason = "idle", ""
    self.tunnelId = self.sessionId = self.peerTunnel = self.peerSession = 0
    self.ns = self.nr = 0
    self.now = self.lastRx = None
    self.framing = FRAMING_SYNC
    self.sentFlag = False
    # one control message is outstanding at a time, so the peer's receive window is never exceeded
    self.pending, self.queue = None, []
    self.waitDeadline = None

  def _log(self, message):
    self.onLog(f"L2TP {message}")

  def open(self):
    if self._state != "idle":
      return

    self.tunnelId, self.sessionId = _newId(), _newId()
    self._state = "tunnel"
    self._log("starting tunnel setup")
    self.queue.append((0, _messageAvps(
      SCCRQ,
      _avp(AVP_VERSION, bytes([1, 0])),
      _number(AVP_FRAMING_CAPS, 3),
      _avp(AVP_HOST_NAME, (self.hostName or "localhost").encode("utf-8")[:200]),
      _number(AVP_TUNNEL_ID, self.tunnelId, 2),
      _number(AVP_WINDOW, 4, 2)
    ), SCCRQ))
    self._pump()

  def close(self):
    if self._state in ("closed", "failed"):
      return

    if self._state in ("session", "up"):
      # shutdown is best effort, so neither message is tracked for an acknowledgement
      if self.peerSession:
        self._transmit(self.peerSession, _messageAvps(CDN, _number(AVP_RESULT, 3, 2), _number(AVP_SESSION_ID, self.sessionId, 2)), CDN, False)

      self._transmit(0, _messageAvps(STOPCCN, _number(AVP_TUNNEL_ID, self.tunnelId, 2), _number(AVP_RESULT, 1, 2)), STOPCCN, False)

    self._finish("closed", "")

  def _finish(self, state, reason):
    self._state, self._failReason = state, reason
    self.pending, self.queue = None, []

  def _fail(self, reason):
    if self._state in ("closed", "failed"):
      return

    self._finish("failed", reason)
    self._log(f"failed: {reason}")

  def _delay(self, tries):
    return min(1.0 * 2 ** (tries - 1), 8.0)

  def _transmit(self, sessionId, avps, kind, track = True):
    datagram = _buildControl(self.peerTunnel, sessionId, self.ns, self.nr, avps)
    self.waitDeadline = None

    if track:
      self.pending = [datagram, 1, None if self.now is None else self.now + self._delay(1), self.ns, kind]

    self.ns = (self.ns + 1) & 0xFFFF
    self.sentFlag = True
    self._log(f"sending {MESSAGE_NAMES[kind]}")
    self.send(datagram)

  def _pump(self):
    if self.pending is None and self.queue and self._state in ACTIVE_STATES:
      self._transmit(*self.queue.pop(0))

  def _sendZlb(self):
    self.send(_buildControl(self.peerTunnel, 0, self.ns, self.nr))

  def tick(self, now):
    try:
      self.now = now

      if self._state not in ACTIVE_STATES:
        return

      if self.lastRx is None:
        self.lastRx = now

      if (pending := self.pending) is not None:
        if pending[2] is None:
          pending[2] = now + self._delay(pending[1])
        elif now >= pending[2]:
          if pending[1] >= (3 if pending[4] == HELLO else 5):
            self._fail("L2TP keepalive lost" if pending[4] == HELLO else "L2TP peer did not answer")
          else:
            pending[1] += 1
            pending[2] = now + self._delay(pending[1])
            self._log(f"{MESSAGE_NAMES[pending[4]]} retransmission {pending[1]}")
            self.send(pending[0])
      elif not self.queue and self._state in ("tunnel", "session"):
        if self.waitDeadline is None:
          # after an ack the peer owes a reply. this bounds that wait during setup, where hello does not run yet
          self.waitDeadline = now + 30.0
        elif now >= self.waitDeadline:
          self._fail("L2TP peer did not answer")
      elif not self.queue and self._state == "up" and self.helloInterval > 0 and now - self.lastRx >= self.helloInterval:
        self.queue.append((0, _messageAvps(HELLO), HELLO))

      self._pump()
    except Exception as e:
      self._log(f"timer error ({type(e).__name__})")

  def sendPpp(self, frame):
    if self._state == "up":
      self.send(pack(">HHH", 0x0002, self.peerTunnel, self.peerSession) + bytes(frame))

  def receive(self, datagram):
    try:
      return self._handle(bytes(datagram))
    except Exception as e:
      self._log(f"dropped datagram ({e if isinstance(e, L2tpError) else type(e).__name__})")

      return None

  def _handle(self, data):
    if self._state not in ACTIVE_STATES:
      return None

    control, tunnel, session, ns, nr, body = _parseHeader(data)

    if tunnel != self.tunnelId:
      raise L2tpError("tunnel id is not ours")

    if control:
      if session not in (0, self.sessionId):
        raise L2tpError("session id is not ours")

      self._handleControl(ns, nr, body)

      return None

    if session != self.sessionId or self._state != "up":
      raise L2tpError("data message for no session")

    self.lastRx = self.now

    return body or None

  def _handleControl(self, ns, nr, body):
    # parse first so a malformed message changes nothing
    avps = _parseAvps(body)

    if body and (avps[0][1] or avps[0][2:4] != (0, AVP_MESSAGE_TYPE) or len(avps[0][4]) < 2):
      raise L2tpError("control message does not open with its type")

    messageType = int.from_bytes(avps[0][4][:2], "big") if body else None

    self.lastRx = self.now

    if self.pending is not None and 0 < (nr - self.pending[3]) & 0xFFFF < 0x8000:
      self.pending = None

    if not body:
      return self._pump()

    if ns != self.nr:
      # an old number is a retransmission whose ack was lost. a future one waits for the peer to resend
      if (self.nr - ns) & 0xFFFF < 0x8000:
        self._log("duplicate control message acknowledged again")
        self._sendZlb()
      else:
        self._log("out of order control message dropped")

      return

    self.nr = (self.nr + 1) & 0xFFFF
    self.sentFlag = False
    values = {}

    for mandatory, hidden, vendor, kind, value in avps:
      if vendor == 0 and not hidden:
        values.setdefault(kind, value)

    if any(mandatory and (hidden or vendor or kind not in KNOWN_AVPS) for mandatory, hidden, vendor, kind, value in avps):
      return self._refuse(messageType, values)

    self._dispatch(messageType, values)
    self._pump()

    if not self.sentFlag:
      self._sendZlb()

  def _refuse(self, messageType, values):
    # rfc 2661 section 4.2 ends the call or tunnel on a mandatory avp we cannot honour. error 8 names that cause
    result = _avp(AVP_RESULT, pack(">HH", 2, 8))

    if not self.peerTunnel and len(values.get(AVP_TUNNEL_ID, b"")) >= 2:
      self.peerTunnel = int.from_bytes(values[AVP_TUNNEL_ID][:2], "big")

    if messageType in (ICRP, ICCN, CDN) and (session := self.peerSession or int.from_bytes(values.get(AVP_SESSION_ID, b"\x00\x00")[:2], "big")):
      self._transmit(session, _messageAvps(CDN, result, _number(AVP_SESSION_ID, self.sessionId, 2)), CDN, False)

    self._transmit(0, _messageAvps(STOPCCN, _number(AVP_TUNNEL_ID, self.tunnelId, 2), result), STOPCCN, False)
    self._fail("L2TP peer sent an unsupported mandatory AVP")

  def _dispatch(self, messageType, avps):
    self._log(f"received {MESSAGE_NAMES.get(messageType, messageType)}")

    if messageType == STOPCCN:
      text = _resultText(avps.get(AVP_RESULT))
      self._fail(f"L2TP server refused the tunnel{text}") if self._state == "tunnel" else self._finish("closed", f"L2TP server closed the tunnel{text}")
    elif messageType == CDN:
      text = _resultText(avps.get(AVP_RESULT))
      self._fail(f"L2TP server refused the session{text}") if self._state == "session" else self._finish("closed", f"L2TP server ended the call{text}")
    elif messageType == SCCRP and self._state == "tunnel":
      self._onTunnelReply(avps)
    elif messageType == ICRP and self._state == "session" and not self.peerSession:
      self._onSessionReply(avps)
    elif messageType != HELLO:
      self._log("unexpected message ignored")

  def _onTunnelReply(self, avps):
    if len(avps.get(AVP_TUNNEL_ID, b"")) < 2 or not (peerTunnel := int.from_bytes(avps[AVP_TUNNEL_ID][:2], "big")):
      return self._fail("L2TP server reply carried no tunnel ID")

    self.peerTunnel = peerTunnel
    capabilities = int.from_bytes(avps.get(AVP_FRAMING_CAPS, b"\x00\x00\x00\x02")[:4], "big")
    # sync framing is what servers expect from a ppp client. async (1) only when the peer offers nothing else
    self.framing = 1 if capabilities & 1 and not capabilities & 2 else FRAMING_SYNC
    self._state = "session"
    self.queue.append((0, _messageAvps(SCCCN), SCCCN))
    self.queue.append((0, _messageAvps(
      ICRQ,
      _number(AVP_SESSION_ID, self.sessionId, 2),
      _number(AVP_SERIAL, _newId()),
      _number(AVP_BEARER_TYPE, 0)
    ), ICRQ))

  def _onSessionReply(self, avps):
    if len(avps.get(AVP_SESSION_ID, b"")) < 2 or not (peerSession := int.from_bytes(avps[AVP_SESSION_ID][:2], "big")):
      return self._fail("L2TP server reply carried no session ID")

    self.peerSession = peerSession
    self.queue.append((peerSession, _messageAvps(ICCN, _number(AVP_TX_SPEED, 100000000), _number(AVP_FRAMING_TYPE, self.framing)), ICCN))
    self._state = "up"
    self._log("session established")
# ---------------------------------------------------------------------------- #
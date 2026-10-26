# ---------------------------------------------------------------------------- #
# DESCRIPTION: packet plumbing under l2tp: the udp header inside esp, the plain udp path and
# the adapter reader thread that feeds the socket thread through a bounded queue
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import socket
import threading

from queue import Full, Queue
from struct import pack, unpack

from modules.esp import EspError
from modules.wintun import WintunClosed
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
L2TP_PORT = 1701
UDP_PROTOCOL = 17
UDP_HEADER = 8
NAT_KEEPALIVE = b"\xff"

def _udpChecksum(sourceIp, destinationIp, segment):
  # rfc 768: ones' complement sum over the ipv4 pseudo header and the segment with a zero checksum
  data = socket.inet_aton(sourceIp) + socket.inet_aton(destinationIp) + pack(">BBH", 0, UDP_PROTOCOL, len(segment)) + segment
  data += bytes(len(data) % 2)
  total = sum(unpack(f">{len(data) // 2}H", data))

  while total >> 16:
    total = (total & 0xFFFF) + (total >> 16)

  # a computed zero is sent as all ones, because zero on the wire means no checksum
  return (~total & 0xFFFF) or 0xFFFF

def _buildUdp(payload, sourceIp, destinationIp, sourcePort = L2TP_PORT, destinationPort = L2TP_PORT):
  # without a known local address the checksum stays zero, which ipv4 allows
  if (length := UDP_HEADER + len(payload)) > 0xFFFF:
    raise ValueError("udp payload is too long")

  header = pack(">HHH", sourcePort, destinationPort, length)
  checksum = _udpChecksum(sourceIp, destinationIp, header + bytes(2) + payload) if sourceIp else 0

  return header + pack(">H", checksum) + payload

def _parseUdp(datagram):
  # the checksum is not verified: under nat-t the peer computes it over addresses we cannot know
  if len(datagram) < UDP_HEADER:
    raise ValueError("udp datagram is truncated")

  sourcePort, destinationPort, length = unpack(">HHH", datagram[:6])

  if not UDP_HEADER <= length <= len(datagram):
    raise ValueError("udp length field is invalid")

  return sourcePort, destinationPort, bytes(datagram[UDP_HEADER:length])

def _dropReason(error):
  # only the own esp and udp texts are shown. a library error is reduced to its type
  return text if (text := str(error)).startswith(("esp", "udp")) else type(error).__name__

def localAddressFor(serverIp, port):
  # a connected udp socket names the interface address the system routes to the server through
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
      probe.connect((serverIp, port))

      return probe.getsockname()[0]
  except OSError:
    return ""

def _localPortOf(sock):
  try:
    return int(sock.getsockname()[1])
  except (OSError, AttributeError, TypeError, IndexError, ValueError):
    return 0

def describeDatagram(datagram):
  # what a datagram on the nat-t port is, from its first bytes only (rfc 3948 section 2)
  if datagram == NAT_KEEPALIVE:
    return "NAT keepalive"

  if len(datagram) < 8:
    return "too short for ESP"

  if datagram[:4] == bytes(4):  # non-esp marker
    return "IKE (non-ESP marker)"

  spi, seq = unpack(">II", datagram[:8])

  return f"ESP spi 0x{spi:08x} sequence {seq}"

class EspTransport:
  # l2tp datagrams travel as udp 1701 inside esp transport mode inside udp 4500
  def __init__(self, sock, serverIp, peerPort, channel, localIp, onLog):
    self.sock, self.serverIp, self.peerPort, self.channel, self.localIp, self.onLog = sock, serverIp, peerPort, channel, localIp, onLog
    self.l2tpPort = L2TP_PORT
    self.localPort = _localPortOf(sock)
    # plain counters keep the diagnostics at one addition per packet
    self.sent = self.received = self.keepalives = self.keepalivesSent = 0
    self.drops = {}

  def _drop(self, reason, text):
    # the first drop of a reason is logged with its detail, the rest are only counted
    self.drops[reason] = count = self.drops.get(reason, 0) + 1

    if count == 1:
      self.onLog(f"ESP {text}. repeats are counted")

  def send(self, datagram):
    if (channel := self.channel) is None:
      return

    try:
      packet = channel.seal(_buildUdp(bytes(datagram), self.localIp, self.serverIp, L2TP_PORT, self.l2tpPort), UDP_PROTOCOL)
      self.sock.sendto(packet, (self.serverIp, self.peerPort))
    except EspError as e:
      return self._drop(e.reason, f"outbound datagram dropped ({e})")
    except ValueError as e:
      return self._drop("size", f"outbound datagram dropped ({_dropReason(e)})")
    except OSError as e:
      return self._drop("send", f"outbound datagram dropped ({type(e).__name__})")

    self.sent += 1

    if self.sent == 1:
      self.onLog(f"ESP first packet sent: {describeDatagram(packet)}, {len(packet)} bytes, local port {self.localPort} to {self.serverIp}:{self.peerPort}")

  def keepalive(self):
    # rfc 3948 section 2.3: a one-octet 0xff payload, sent where the esp goes
    try:
      self.sock.sendto(NAT_KEEPALIVE, (self.serverIp, self.peerPort))
      self.keepalivesSent += 1
    except OSError as e:
      self._drop("send", f"NAT keepalive dropped ({type(e).__name__})")

  def unwrap(self, datagram, address):
    # return the l2tp datagram, or None after counting why the packet was dropped
    if datagram == NAT_KEEPALIVE:
      self.keepalives += 1

      return None

    if (channel := self.channel) is None:
      return None

    try:
      segment, nextHeader = channel.open(bytes(datagram))
    except EspError as e:
      return self._drop(e.reason, f"inbound datagram dropped ({e})")
    except ValueError as e:
      return self._drop("esp", f"inbound datagram dropped ({_dropReason(e)})")

    self.received += 1

    if self.received == 1:
      self.onLog(f"ESP first packet received: {describeDatagram(datagram)}, {len(datagram)} bytes from {address[0]}:{address[1]}")

    if nextHeader != UDP_PROTOCOL:
      return self._drop("protocol", f"inbound datagram dropped (esp payload is protocol {nextHeader}, not udp)")

    try:
      sourcePort, destinationPort, body = _parseUdp(segment)
    except ValueError as e:
      return self._drop("udp", f"inbound datagram dropped ({e})")

    if destinationPort != L2TP_PORT:
      return self._drop("port", f"inbound datagram dropped (udp {sourcePort} to {destinationPort} is not addressed to l2tp)")

    # rfc 2661 lets the server answer from another port, and later messages go there
    self.l2tpPort = sourcePort

    return body

  def summary(self):
    reasons = ", ".join(f"{reason} {count}" for reason, count in self.drops.items())
    keepalives = "".join(f", NAT keepalives {kind} {count}" for kind, count in (("sent", self.keepalivesSent), ("received", self.keepalives)) if count)

    return f"ESP: sent {self.sent}, received {self.received}, dropped {sum(self.drops.values())}" + (f" ({reasons})" if reasons else "") + keepalives

class PlainTransport:
  # plain l2tp: the datagrams are the udp payload of the socket itself
  def __init__(self, sock, serverIp, port, onDrop):
    self.sock, self.serverIp, self.port, self.onDrop = sock, serverIp, port, onDrop

  def send(self, datagram):
    try:
      self.sock.sendto(bytes(datagram), (self.serverIp, self.port))
    except OSError as e:
      self.onDrop(f"outbound datagram dropped ({type(e).__name__})")

  def unwrap(self, datagram, address):
    self.port = address[1]

    return bytes(datagram)

class AdapterReader:
  # the only job of this thread is to read the adapter and hand packets on without ever blocking
  def __init__(self, adapter, onLog, size = 256, timeoutMs = 100):
    self.adapter, self.onLog, self.timeoutMs = adapter, onLog, timeoutMs
    self.queue = Queue(maxsize = size)
    self.stopEvent = threading.Event()
    self.thread = None
    self.dropped = 0
    self.closed = False

  def start(self):
    self.thread = threading.Thread(target = self._run, name = "adapter-reader", daemon = True)
    self.thread.start()

  def _run(self):
    while not self.stopEvent.is_set():
      try:
        packet = self.adapter.read(self.timeoutMs)
      except WintunClosed:
        break
      except Exception as e:
        self.onLog(f"adapter read failed ({type(e).__name__})")
        break

      if packet:
        self._offer(packet)

    # an end nobody asked for means the adapter went away under the session
    self.closed = not self.stopEvent.is_set()

  def _offer(self, packet):
    try:
      self.queue.put_nowait(packet)
    except Full:
      self.dropped += 1

      if self.dropped == 1:
        self.onLog("outbound queue is full, packets are being dropped")

  def alive(self):
    return self.thread is not None and self.thread.is_alive()

  def stop(self, timeout):
    # return whether the thread is gone, which the adapter close depends on
    self.stopEvent.set()

    if self.thread is not None and self.thread is not threading.current_thread():
      self.thread.join(timeout)

    return not self.alive()
# ---------------------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #
# DESCRIPTION: tunnel session state machine: connects ike, esp, l2tp, ppp, the adapter and the
# routes in order, runs the socket thread and undoes everything through one teardown
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import math
import socket
import threading
import time

from enum import Enum
from os import path
from queue import Empty
from traceback import extract_tb
from dataclasses import dataclass
from collections.abc import Callable

from PyQt5.QtCore import QObject, pyqtSignal

import modules.logger as logger
import modules.network as network
import modules.recovery as recovery

from modules.dataplane import AdapterReader, EspTransport, PlainTransport, describeDatagram, localAddressFor
from modules.ike import DEFAULT_PROPOSALS, IkeError, IkeSession, isIke
from modules.l2tp import L2tpTunnel
from modules.metadata import APP_NAME
from modules.network import NetworkError
from modules.ppp import AUTH_OPTIONS, PppSession
from modules.wintun import WintunAdapter
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
RESOLVE_SLICE = 0.05
MIN_MTU = 576
# the ppp mru is 1400, and a larger inner packet would fragment the outer one
MAX_MTU = 1400
NAT_T_PORT = 4500

CIPHER_NAMES = {"aes256": "AES-256", "aes128": "AES-128", "3des": "3DES"}
HASH_NAMES = {"sha256": "SHA-256", "sha1": "SHA-1"}
INNER_CHECKSUMS = ("auto", "zero")
CHECKSUM_CHOICES = ", ".join(INNER_CHECKSUMS)
MPPE_MODES = ("auto", "required", "off")
MPPE_CHOICES = ", ".join(MPPE_MODES)
AUTH_CHOICES = ", ".join(AUTH_OPTIONS)

class TunnelState(Enum):
  DISCONNECTED = "disconnected"
  CONNECTING = "connecting"
  CONNECTED = "connected"
  DISCONNECTING = "disconnecting"
  FAILED = "failed"

class TunnelFailure(Exception):
  def __init__(self, message, field = ""):
    super().__init__(message)
    self.message, self.field = message, field

class Cancelled(Exception):
  pass

def _openUdpSocket(port):
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

  try:
    # no other process may bind the same port and read the ike and esp datagrams
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    sock.bind(("0.0.0.0", port))
  except OSError:
    sock.close()
    raise

  return sock

def _resolveIpv4(host):
  return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]

@dataclass
class TunnelFactories:
  # every outside dependency of a session, injectable as one unit
  socket: Callable = _openUdpSocket
  adapter: Callable = WintunAdapter
  network: object = network
  ike: Callable = IkeSession
  l2tp: Callable = L2tpTunnel
  ppp: Callable = PppSession
  resolve: Callable = _resolveIpv4
  localAddress: Callable = localAddressFor
  clock: Callable = time.monotonic

def validate(profile):
  if not profile.server.strip():
    return "enter the server address", "server"

  if profile.ipsecEnabled and not profile.psk:
    return "enter the pre-shared key, or turn IPsec off", "psk"

  if not profile.username.strip():
    return "enter the username", "username"

  # hand-edited advanced keys are checked here, so a bad value never reaches the worker
  if not MIN_MTU <= profile.mtu <= MAX_MTU:
    return f"mtu must be between {MIN_MTU} and {MAX_MTU} in the profile", ""

  for name in ("port", "ikePort"):
    if not 1 <= getattr(profile, name) <= 65535:
      return f"{name} must be between 1 and 65535 in the profile", ""

  if profile.innerChecksum not in INNER_CHECKSUMS:
    return f"innerChecksum must be one of {CHECKSUM_CHOICES} in the profile", ""

  if profile.mppe not in MPPE_MODES:
    return f"mppe must be one of {MPPE_CHOICES} in the profile", ""

  if not any(method in AUTH_OPTIONS for method in profile.authMethods):
    return f"authMethods must name at least one of {AUTH_CHOICES} in the profile", ""

  return None

def _where(e):
  # file and line only: the text of an unexpected error may carry anything, secrets included
  frames = extract_tb(e.__traceback__) if e.__traceback__ else []

  return f"{path.basename(frames[-1].filename)}:{frames[-1].lineno}" if frames else "unknown place"

class TunnelSession(QObject):
  stateChanged = pyqtSignal(object)
  stageChanged = pyqtSignal(str)
  infoChanged = pyqtSignal(dict)
  trafficChanged = pyqtSignal(float, float)
  logLine = pyqtSignal(str)
  failed = pyqtSignal(str, str)

  def __init__(self, factories = None):
    super().__init__()
    self.factories = factories or TunnelFactories()
    self.clock = self.factories.clock
    self.lock = threading.Lock()
    self.teardownLock = threading.Lock()
    self._state = TunnelState.DISCONNECTED
    self.worker = None
    self.cancelEvent = threading.Event()
    self.undo = []
    self._reset()

  state = property(lambda self: self._state)

  def _reset(self):
    self.ike = self.l2tp = self.ppp = self.adapter = self.reader = self.transport = None
    self.sock = self.ikeSock = self.floatSock = self.snapshot = self.hostRoute = None
    self.serverIp, self.ipsecText, self.pppText = "", "off", ""
    self.ikeStage, self.ikeEstablishedAt, self.ikeLifetime = "", None, 0
    self.dpdInterval, self.nextDpd, self.nextTick = 0.0, 0.0, 0.0
    self.connectedAt = self.trafficAt = None
    self.down = self.up = 0
    self.drops = {}
    self.datagramsIn = self.ikeIn = self.foreignIn = 0
    self.keepaliveMark, self.lastOutAt = 0, 0.0
    self.keepRecovery = self.rekeyWarned = False

  # PUBLIC INTERFACE -------------------------------------------------------- #
  def connectTo(self, profile):
    if self.isBusy():
      self._log("a connection is already in progress")

      return

    if problem := validate(profile):
      self.failed.emit(*problem)
      self._setState(TunnelState.FAILED)

      return

    self._reset()
    self.cancelEvent = threading.Event()
    self._setState(TunnelState.CONNECTING)
    self.worker = threading.Thread(target = self._run, args = (profile,), name = "tunnel-socket", daemon = True)
    self.worker.start()

  def disconnect(self):
    # idempotent: only a live attempt or session is cancelled, the worker does the teardown
    with self.lock:
      if self._state not in (TunnelState.CONNECTING, TunnelState.CONNECTED) or self.cancelEvent.is_set():
        return

      self.cancelEvent.set()
      self._state = TunnelState.DISCONNECTING

    self.stateChanged.emit(TunnelState.DISCONNECTING)

  def isBusy(self):
    return self.worker is not None and self.worker.is_alive()

  def wait(self, timeout = None):
    # return whether the worker has ended, for a caller that must not leave before the teardown
    if self.worker is not None and self.worker is not threading.current_thread():
      self.worker.join(timeout)

    return not self.isBusy()

  # HELPERS ----------------------------------------------------------------- #
  def _log(self, message):
    self.logLine.emit(message)

  def _setState(self, state):
    with self.lock:
      self._state = state

    self.stateChanged.emit(state)

  def _checkCancel(self):
    if self.cancelEvent.is_set():
      raise Cancelled()

  def _stage(self, text):
    self._checkCancel()
    self.stageChanged.emit(text)
    self._log(text)

  def _push(self, name, action):
    self.undo.append((name, action))

  def _guard(self, call, field = ""):
    # the network modules raise readable texts of their own
    try:
      return call()
    except NetworkError as e:
      raise TunnelFailure(str(e), field) from None

  def _dropped(self, reason):
    # the first drop of a kind is logged, the rest only counted, so a flood cannot fill the log
    self.drops[reason] = self.drops.get(reason, 0) + 1

    if self.drops[reason] == 1:
      self._log(f"{reason}. repeats are counted")

  def _ikeClock(self):
    # a cancel makes every ike deadline pass at once, which ends a blocking negotiation
    return math.inf if self.cancelEvent.is_set() else self.clock()

  def _ikeLog(self, message):
    self._log(message)

    if self.ike is not None and getattr(self.ike, "stage", "") == "quick" and self.ikeStage != "quick":
      self.ikeStage = "quick"
      self.stageChanged.emit("IKE phase 2")

  # WORKER ------------------------------------------------------------------ #
  def _run(self, profile):
    failure = None

    try:
      self._establish(profile)
      self._serve()
    except Cancelled:
      pass
    except TunnelFailure as e:
      failure = e
    except Exception as e:
      logger.warning(f"tunnel stopped by {type(e).__name__} at {_where(e)}")
      self._log(f"internal error ({type(e).__name__})")

      failure = TunnelFailure("the connection failed unexpectedly")

    # a cancel that came first wins over the failure it caused, such as an interrupted negotiation.
    # a failure that came first wins over a disconnect pressed during its long teardown
    if failure is not None and self.cancelEvent.is_set():
      failure = None

    try:
      if failure is not None:
        self._log(f"connection failed: {failure.message}")

      self._teardown()
    except Exception as e:
      logger.warning(f"teardown stopped by {type(e).__name__} at {_where(e)}")

    # the final state is always emitted, or the window would stay in disconnecting
    try:
      if failure is not None:
        self.failed.emit(failure.message, failure.field)
      else:
        self._log("disconnected")
    finally:
      self._setState(TunnelState.FAILED if failure is not None else TunnelState.DISCONNECTED)

  def _establish(self, profile):
    net = self.factories.network
    self._stage("Resolving server")
    self._sweepRecovery()
    self.snapshot = self._guard(net.snapshotDefaultRoute)
    self.serverIp = self._resolve(profile.server.strip())
    self._log(f"server address {self.serverIp}")
    self._openSockets(profile)
    self.hostRoute = self._guard(lambda: net.planRoutes(profile, self.serverIp, self.snapshot, 0, onLog = lambda message: None)[0], "server")
    self._addRoute(self.hostRoute)

    if profile.ipsecEnabled:
      self._negotiate(profile)
    else:
      self.transport = PlainTransport(self.sock, self.serverIp, profile.port, self._dropped)

    self.sock.settimeout(0.02)
    self._openL2tp(profile)
    self._openPpp(profile)
    self._configure(profile)
    self._promote()

  def _sweepRecovery(self):
    # a crash of an earlier session is repaired before anything new is changed
    try:
      recovery.sweep(*self.factories.network.sweepCallbacks())
    except Exception as e:
      logger.warning(f"recovery sweep failed ({type(e).__name__})")

    # a record the sweep could not settle is kept for the next start, never cleared by this session
    self.keepRecovery = recovery.loadRecovery() is not None

  def _resolve(self, host):
    # getaddrinfo cannot be interrupted, so it runs aside and is waited for in short slices
    result = {}

    def work():
      try:
        result["ip"] = self.factories.resolve(host)
      except (OSError, UnicodeError, ValueError, IndexError):
        pass

    helper = threading.Thread(target = work, name = "tunnel-resolve", daemon = True)
    helper.start()

    for _ in range(int(10.0 / RESOLVE_SLICE)):
      helper.join(RESOLVE_SLICE)
      self._checkCancel()

      if not helper.is_alive():
        break

    if "ip" not in result:
      raise TunnelFailure("cannot resolve the server address", "server")

    return result["ip"]

  def _openSocket(self, port):
    sock = self.factories.socket(port)
    self._push(f"socket {port} close", sock.close)

    return sock

  def _openAnySocket(self, port):
    # the wanted port first, then any free one. port 0 is tried once
    for candidate in dict.fromkeys((port, 0)):
      try:
        return self._openSocket(candidate)
      except OSError:
        pass

    raise TunnelFailure("no UDP socket could be opened")

  def _openSockets(self, profile):
    if not profile.ipsecEnabled:
      self.sock = self._openAnySocket(1701)

      return

    # windows hands udp-encapsulated esp arriving on local 4500 to its own ipsec driver and never to a
    # user socket, so the float leaves from an ephemeral port. the server answers whatever port it observes
    self.floatSock = self._openAnySocket(0)
    self.ikeSock = self._openAnySocket(500)

  def _addRoute(self, route):
    added = self._guard(lambda: self.factories.network.addRoute(**route))
    destination, prefix = route["destination"], route["prefix"]

    self._push(f"route {destination}/{prefix} delete", lambda: self.factories.network.deleteRoute(added))

  def _negotiate(self, profile):
    self._stage("IKE phase 1")

    self.ike = self.factories.ike(self.ikeSock, (self.serverIp, profile.ikePort), profile.psk, DEFAULT_PROPOSALS, profile.ikeId, self._ikeLog, floatSock = self.floatSock, clock = self._ikeClock)

    try:
      result = self.ike.negotiate(20.0)
    except IkeError as e:
      self._checkCancel()
      raise TunnelFailure(e.reason, e.field or "") from None

    self._push("ESP drop", self._dropEsp)
    self._push("IKE delete", self.ike.delete)
    self._checkCancel()

    if result.peerPort != NAT_T_PORT:
      raise TunnelFailure(f"the server did not move to NAT traversal on UDP {NAT_T_PORT}, which is required")

    self.sock = result.sock
    self.ikeEstablishedAt, self.ikeLifetime = self.clock(), result.lifetime
    self.dpdInterval = max(float(profile.dpdInterval), 0.0)
    self.nextDpd = self.ikeEstablishedAt + self.dpdInterval
    sa = result.channel.outSa
    self.ipsecText = f"PSK · {CIPHER_NAMES.get(sa.cipher, sa.cipher)} · {HASH_NAMES.get(sa.hashName, sa.hashName)}"
    # rfc 3948 section 3.1.2: a server reached through a nat fixes the inner checksum with the nat-oa address,
    # so the checksum is computed with the very address ike sent as nat-oa initiator
    localIp = ""

    if profile.innerChecksum == "zero":
      self._log("inner UDP checksums are sent as zero")
    elif not (localIp := getattr(self.ike, "localIp", "") or self.factories.localAddress(self.serverIp, NAT_T_PORT)):
      self._log("local address unknown, inner UDP checksums are left at zero")

    self.transport = EspTransport(self.sock, self.serverIp, result.peerPort, result.channel, localIp, self._log)
    self.keepaliveMark, self.lastOutAt = 0, self.clock()
    checksum = f"computed with {localIp}" if localIp else "zero"

    self._log(
      f"ESP outbound spi 0x{result.channel.outSa.spi:08x} (the server's), inbound spi 0x{result.channel.inSa.spi:08x} (ours), "
      f"local port {self.transport.localPort} to {self.serverIp}:{result.peerPort}, inner UDP checksum {checksum}"
    )

  def _dropEsp(self):
    if isinstance(self.transport, EspTransport):
      self.transport.channel = None

  def _openL2tp(self, profile):
    self._stage("L2TP tunnel")

    self.l2tp = self.factories.l2tp(self.transport.send, APP_NAME, profile.helloInterval, self._log)

    self._push("L2TP close", self.l2tp.close)
    self.l2tp.open()
    self._waitUntil(lambda: self.l2tp.state == "up", "L2TP tunnel setup timed out")

  def _openPpp(self, profile):
    self._stage("PPP authentication")

    # ipsec already encrypts, so mppe would only cost time
    mppe = "off" if profile.ipsecEnabled else profile.mppe
    self.ppp = self.factories.ppp(profile.username, profile.password, profile.authMethods, mppe, profile.mtu, self.l2tp.sendPpp, self._log)

    self._push("PPP close", self.ppp.close)
    self.ppp.start()
    self._waitUntil(lambda: self.ppp.state == "up", "PPP negotiation timed out")

    self.pppText = self.ppp.authName + (" · MPPE" if self.ppp.mppeActive else "")

  def _configure(self, profile):
    net = self.factories.network

    self._stage("Configuring network")
    # the close is registered first, so a half-made adapter is released too
    self.adapter = self.factories.adapter()

    self._push("adapter close", self._closeAdapter)
    self._guard(lambda: self.adapter.create(APP_NAME, net.DLL_PATH))
    self._checkCancel()
    self._guard(lambda: self.adapter.setAddress(self.ppp.localIp, profile.mtu))

    self.reader = AdapterReader(self.adapter, self._log)

    self.reader.start()
    self._push("adapter reader stop", lambda: self.reader.stop(2.0))
    self._checkCancel()

    if dns := [server.strip() for server in profile.dns if server.strip()] or self.ppp.dnsServers:
      entry = f"{APP_NAME}:{self.adapter.index}"

      self._push("DNS reset", lambda: net.clearDns(entry))
      self._guard(lambda: net.setDns(self.adapter.index, dns, adapterName = APP_NAME))

    hostKey = (self.hostRoute["destination"], self.hostRoute["prefix"])

    for route in self._guard(lambda: net.planRoutes(profile, self.serverIp, self.snapshot, self.adapter.index, onLog = self._log)):
      if (route["destination"], route["prefix"]) != hostKey:
        self._checkCancel()
        self._addRoute(route)

  def _closeAdapter(self):
    # wintun frees the packet ring on close, so a reader still running would crash the process
    if self.reader is not None and self.reader.alive():
      self._log("the adapter reader did not stop, the adapter is left for the next start")

      return False

    self.adapter.close()

  def _promote(self):
    with self.lock:
      if self.cancelEvent.is_set():
        raise Cancelled()

      self._state = TunnelState.CONNECTED

    self.connectedAt = self.trafficAt = self.clock()
    self.down = self.up = 0

    self.infoChanged.emit({"localIp": self.ppp.localIp, "serverIp": self.serverIp, "ipsec": self.ipsecText, "ppp": self.pppText})
    self._log(f"connected, local address {self.ppp.localIp}")
    self.stateChanged.emit(TunnelState.CONNECTED)

  # SOCKET THREAD ----------------------------------------------------------- #
  def _serve(self):
    while not self.cancelEvent.is_set():
      self._step()

    raise Cancelled()

  def _waitUntil(self, done, timeoutText):
    deadline = self.clock() + 60.0

    while not done():
      self._checkCancel()
      self._step()

      if not done() and self.clock() >= deadline:
        raise TunnelFailure(timeoutText)

  def _step(self):
    self._receive()
    self._drainOutbound()

    now = self.clock()

    if now >= self.nextTick:
      self.nextTick = now + 0.25

      self._tickTimers(now)

    self._checkLink(now)

    if self.connectedAt is not None and (elapsed := now - self.trafficAt) >= 1.0:
      self.trafficChanged.emit(self.down / elapsed, self.up / elapsed)

      self.down = self.up = 0
      self.trafficAt = now

  def _receive(self):
    try:
      data, address = self.sock.recvfrom(65535)
    except TimeoutError:
      return
    except ConnectionResetError:
      # windows reports an icmp port unreachable this way. dpd and hello decide if the peer is gone
      return self._dropped("ICMP unreachable received from the network")
    except OSError:
      raise TunnelFailure("the network connection failed (socket error)") from None

    self._dispatch(data, address)

  def _dispatch(self, data, address):
    if isinstance(self.transport, EspTransport):
      self.datagramsIn += 1

      if self.datagramsIn == 1:
        self._log(f"first datagram after quick mode: {address[0]}:{address[1]} to local port {self.transport.localPort}, {len(data)} bytes, {describeDatagram(data)}")

    if address[0] != self.serverIp:
      self.foreignIn += 1

      if self.foreignIn == 1:
        self._log(f"datagram from another address {address[0]}:{address[1]} dropped. repeats are counted")

      return

    if self.ike is not None and isIke(data):
      self.ikeIn += 1

      return self.ike.handle(data)

    if (payload := self.transport.unwrap(data, address)) is None or (frame := self.l2tp.receive(payload)) is None:
      return

    if self.ppp is None or (packet := self.ppp.receive(frame)) is None or self.reader is None:
      return

    if self.adapter.write(packet):
      self.down += len(packet)

  def _drainOutbound(self):
    if self.reader is None or self.ppp is None:
      return

    # empty the queue before the next receive, but give way to the timers when their turn comes
    while True:
      try:
        packet = self.reader.queue.get_nowait()
      except Empty:
        return

      self.ppp.sendIp(packet)
      self.up += len(packet)

      if self.clock() >= self.nextTick:
        return

  def _tickTimers(self, now):
    for machine in (self.l2tp, self.ppp):
      if machine is not None:
        machine.tick(now)

    self._keepNatAlive(now)

    if self.ike is None or self.ikeEstablishedAt is None:
      return

    if self.dpdInterval > 0 and now >= self.nextDpd:
      self.nextDpd = now + self.dpdInterval
      self.ike.sendDpd()

    # v1 has no in-place rekey: the session ends when the server drops the expired sa
    if not self.rekeyWarned and self.ike.needsRekey(now):
      self.rekeyWarned = True
      self._log("IPsec security association is near the end of its lifetime. rekeying is not supported, the tunnel ends when the server drops it")

  def _keepNatAlive(self, now):
    # rfc 3948 section 4: a lone 0xff after m quiet seconds keeps the nat mapping alive
    if not isinstance(transport := self.transport, EspTransport) or transport.channel is None:
      return

    if transport.sent != self.keepaliveMark:
      self.keepaliveMark, self.lastOutAt = transport.sent, now
    # rfc 3948 section 4: the nat-keepalive interval, which home routers' idle udp timeouts call for
    elif now - self.lastOutAt >= 20.0:
      self.lastOutAt = now
      transport.keepalive()

  def _checkLink(self, now):
    if self.ike is not None and self.ikeEstablishedAt is not None:
      if self.ike.peerDeleted:
        raise TunnelFailure("server closed the connection")

      if not self.ike.dpdAlive(now):
        expired = self.ikeLifetime > 0 and now - self.ikeEstablishedAt >= self.ikeLifetime
        raise TunnelFailure("IPsec security association expired" if expired else "keepalive lost: the server stopped answering")

    if self.l2tp is not None and self.l2tp.state in ("failed", "closed"):
      raise TunnelFailure(self.l2tp.failReason or "server closed the connection")

    if self.ppp is not None and self.ppp.state in ("failed", "closed"):
      raise TunnelFailure(self.ppp.failReason or "server closed the connection", "credentials" if self.ppp.failField in ("username", "password") else "")

    if self.reader is not None and self.reader.closed:
      raise TunnelFailure("the network adapter was closed")

  # TEARDOWN ---------------------------------------------------------------- #
  def _teardown(self):
    # undo in reverse of creation. one failing step never skips the others, and the recovery
    # file is cleared only when everything came back, otherwise the next start sweeps it
    with self.teardownLock:
      steps, self.undo = self.undo, []

      if not steps:
        return True

      complete = True

      for name, action in reversed(steps):
        try:
          if action() is False:
            complete = False
            self._log(f"cleanup step failed: {name}")
        except Exception as e:
          complete = False

          self._log(f"cleanup step failed: {name} ({type(e).__name__})")
          logger.warning(f"cleanup step {name} failed ({type(e).__name__} at {_where(e)})")

      self._reportDrops()

      if self.connectedAt is not None:
        self.trafficChanged.emit(0.0, 0.0)

      leftover = (state := recovery.loadRecovery()) is not None and bool(state.routes or state.dnsInterfaces)

      if not complete or leftover:
        self._log("some changes could not be undone. they are retried at the next start")
      elif not self.keepRecovery:
        recovery.clearRecovery()

      return complete and not leftover

  def _reportDrops(self):
    if isinstance(self.transport, EspTransport):
      self._log(self.transport.summary())
      self._log(f"socket: {self.datagramsIn} datagrams received after quick mode, {self.ikeIn} of them IKE, {self.foreignIn} from other addresses")
    elif self.foreignIn:
      self._log(f"datagrams from other addresses dropped: {self.foreignIn} in total")

    counts = [(reason, count) for reason, count in self.drops.items() if count > 1]

    if self.reader is not None and self.reader.dropped:
      counts.append(("outbound packets dropped on a full queue", self.reader.dropped))

    for reason, count in counts:
      self._log(f"{reason}: {count} in total")
# ---------------------------------------------------------------------------- #
# -*- coding: utf-8 -*-

# DEPENDENCIES --------------------------------------------------------------- #
import re
import math
import time

from pathlib import Path
from dataclasses import replace
from os import environ, chdir
from sys import exit as sysExit
from sys import argv
from ctypes import WinDLL, c_void_p, get_last_error

# external
from PyQt5 import QtCore, QtWidgets, QtGui

# custom
from gui import Ui_mainWindow
from modules.resources import *
from modules.metadata import APP_NAME, APP_VERSION, DESCRIPTION, DISCLAIMER
from modules.paths import exeDirectory, isFrozen
from modules.profiles import Profile, loadProfiles, saveProfiles
from modules.settings import loadSettings, saveSettings
from modules.widgets import ChoiceDialog
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
NEW_PROFILE_NAME = "New profile"
EMPTY_VALUE = "—"

# status dot colours. amber also blinks, dimmed in between
AMBER, RED = "#e8a020", "#c74040"

INPUT_NAMES = ("server_input", "username_input", "password_input", "psk_input")

SPEED_UNITS = ("B/s", "KB/s", "MB/s", "GB/s")

def cleanRate(value):
  # nan, infinity and negatives come from a broken clock or a counter reset. none may crash a slot
  value = float(value)

  return value if 0 <= value < math.inf else 0.0

def formatSpeed(bytesPerSecond):
  # 1024 base. the value is rounded first, so 1048575 reads 1.0 MB/s and not 1024.0 KB/s
  value, unit = cleanRate(bytesPerSecond), 0

  while unit < len(SPEED_UNITS) - 1 and round(value, 1 if unit else 0) >= 1024:
    value, unit = value / 1024, unit + 1

  return f"{round(value)} {SPEED_UNITS[0]}" if unit == 0 else f"{value:.1f} {SPEED_UNITS[unit]}"

def barValue(bytesPerSecond):
  # logarithmic, so a few KB/s and a few MB/s both move the bar. full scale is 1 Gbit/s
  return min(100, int(100 * math.log10(1 + cleanRate(bytesPerSecond)) / math.log10(1 + 125_000_000)))

def formatElapsed(seconds):
  minutes, secs = divmod(int(max(seconds, 0)), 60)
  hours, minutes = divmod(minutes, 60)

  return f"{hours}:{minutes:02}:{secs:02}" if hours else f"{minutes:02}:{secs:02}"

def uniqueName(base, taken):
  name, number = base, 2

  while name in taken:
    name, number = f"{base} ({number})", number + 1

  return name

def snapshotOf(profile):
  # what the form can express. secrets count only while they are remembered, since otherwise
  # they are never stored and a typed one must not make the profile look changed
  secrets = (profile.password, profile.psk) if profile.remember else ("", "")

  return (profile.name, profile.server.strip(), profile.username, *secrets, profile.ipsecEnabled, profile.routeAll, profile.remember)

# RUNTIME -------------------------------------------------------------------- #
def loadRuntime():
  # the logger reads its folder when first imported, so everything that reaches it waits
  # for main() to anchor the working directory and pass the singleton and elevation checks
  global logger, network, recovery, TunnelSession, TunnelState
  global EDITABLE_STATES, LIVE_STATES, BLINKING_STATES, STATE_COLOURS, STATE_TEXTS

  import modules.logger as logger
  import modules.network as network
  import modules.recovery as recovery

  from modules.tunnel import TunnelSession, TunnelState

  EDITABLE_STATES = (TunnelState.DISCONNECTED, TunnelState.FAILED)
  LIVE_STATES = (TunnelState.CONNECTING, TunnelState.CONNECTED)
  BLINKING_STATES = (TunnelState.CONNECTING, TunnelState.DISCONNECTING)
  STATE_COLOURS = {
    TunnelState.DISCONNECTED: "rgba(255,255,255,0.15)",
    TunnelState.CONNECTING: AMBER,
    TunnelState.CONNECTED: "#5aab5a",
    TunnelState.DISCONNECTING: AMBER,
    TunnelState.FAILED: RED
  }
  STATE_TEXTS = {
    TunnelState.DISCONNECTED: "Disconnected",
    TunnelState.CONNECTING: "Connecting…",
    TunnelState.CONNECTED: "Connected",
    TunnelState.DISCONNECTING: "Disconnecting…",
    TunnelState.FAILED: "Failed"
  }

def sweepAtStartup():
  # a crashed earlier run is repaired before the window opens. a failure here only logs
  try:
    recovery.sweep(*network.sweepCallbacks())
  except Exception as e:
    logger.warning(f"startup recovery sweep failed ({type(e).__name__})")

class MainWindow(QtWidgets.QMainWindow):
  def __init__(self, onClose):
    super().__init__()
    self.onClose = onClose

  def closeEvent(self, event):
    # the tunnel is torn down before the process may leave
    self.onClose()
    event.accept()

class Controller(QtCore.QObject):
  def __init__(self):
    super().__init__()

    self.session = TunnelSession()
    self.dllPath = Path(network.DLL_PATH)
    self.window = MainWindow(self.shutDown)
    self.ui = Ui_mainWindow()

    self.ui.setupUi(self.window)

    self.state = None
    self.stage = ""
    self.failureText = ""
    self.connectedAt = None
    self.blinkOn = True
    self.loading = False
    self.notice = ""
    self.shownIndex = -1
    self.closing = False
    self.links = []
    self.profiles = []
    self.drafts = set()
    self.settings = loadSettings()
    self.blinkTimer = QtCore.QTimer(self)

    self.blinkTimer.setInterval(600)
    self.blinkTimer.timeout.connect(self._blinkStep)

    self.clockTimer = QtCore.QTimer(self)

    self.clockTimer.setInterval(1000)

    self.clockTimer.timeout.connect(self._tickClock)
    self._setupStatic()
    self._connectSignals()
    self._loadProfileList()
    self._applyState(self.session.state)

  # -------------------------------------------------------------------------- #
  def _setupStatic(self):
    ui = self.ui

    ui.programName.setText(APP_NAME)
    ui.programDescription.setText(DESCRIPTION)
    ui.adapter.setText("Wintun ready" if self.dllPath.is_file() else "wintun.dll missing")
    ui.logPanel.appendPlainText(DISCLAIMER)
    ui.downloadBar.setRange(0, 100)
    ui.uploadBar.setRange(0, 100)
    ui.saveProfile_button.setShortcut(QtGui.QKeySequence("Ctrl+S"))

  def _connectSignals(self):
    ui, session = self.ui, self.session

    self.links = [
      (session.stateChanged, self._onStateChanged), (session.stageChanged, self._onStage), (session.infoChanged, self._onInfo),
      (session.trafficChanged, self._onTraffic), (session.logLine, self._appendLog), (session.failed, self._onFailed)
    ]

    for signal, slot in self.links:
      signal.connect(slot)

    ui.connect_button.clicked.connect(self._onConnect)
    ui.disconnect_button.clicked.connect(self.session.disconnect)
    ui.newProfile_button.clicked.connect(self.newProfile)
    ui.saveProfile_button.clicked.connect(self.saveProfile)
    ui.deleteProfile_button.clicked.connect(self.deleteProfile)
    ui.profile_combo.currentIndexChanged.connect(self._onProfileSelected)

    for name in INPUT_NAMES:
      widget = getattr(ui, name)
      widget.textChanged.connect(lambda _, widget = widget: self._onEdited(widget))

    ui.ipsec_checkbox.toggled.connect(self._onToggled)
    ui.routeAll_checkbox.toggled.connect(self._onToggled)
    ui.remember_checkbox.toggled.connect(self._onToggled)

  # -------------------------------------------------------------------------- #
  def _onStateChanged(self, state):
    # a value queued from the worker may be stale next to one emitted from the ui thread, so the
    # session's own state decides
    self._applyState(self.session.state)

  def _applyState(self, state):
    previous, self.state = self.state, state
    ui = self.ui
    self.notice = ""

    ui.disconnect_button.setEnabled(state in LIVE_STATES)
    self._refreshEnabled()

    if state != TunnelState.FAILED:
      self._clearInvalid()
      self.failureText = ""

    if state == TunnelState.CONNECTING and previous != state:
      self.stage = ""

    if state == TunnelState.CONNECTED and previous != state:
      self.connectedAt = time.monotonic()
      self.clockTimer.start()
      self._tickClock()
    elif state != TunnelState.CONNECTED:
      self.clockTimer.stop()
      self.connectedAt = None
      ui.sessionTimer.setText("00:00")

    if state != TunnelState.CONNECTED and previous != state:
      self._resetSessionValues()

    for name in (
      "sessionStatus", "sessionTimer", "localIp", "serverIp", "ipsecInfo", "pppInfo",
      "downloadSpeed", "uploadSpeed", "downloadLabel", "uploadLabel", "downloadBar", "uploadBar"
    ):
      getattr(ui, name).setEnabled(state == TunnelState.CONNECTED)

    if state in BLINKING_STATES:
      if not self.blinkTimer.isActive():
        self.blinkOn = True
        self.blinkTimer.start()
    else:
      self.blinkTimer.stop()

    self._showStatus()
    self._refreshDirty()

  def _refreshEnabled(self):
    ui, editable = self.ui, self.state in EDITABLE_STATES

    for name in (
      "profile_combo", "newProfile_button", "deleteProfile_button", "server_input", "username_input", "password_input",
      "ipsec_checkbox", "routeAll_checkbox", "remember_checkbox", "connect_button"
    ):
      getattr(ui, name).setEnabled(editable)

    ui.psk_input.setEnabled(editable and ui.ipsec_checkbox.isChecked())

  def _resetSessionValues(self):
    ui = self.ui

    for name in ("localIp", "serverIp", "ipsecInfo", "pppInfo"):
      getattr(ui, name).setText(EMPTY_VALUE)

    self._showTraffic(0.0, 0.0)

  def _showStatus(self):
    ui, state = self.ui, self.state
    text = STATE_TEXTS[state]
    statusText = text

    if state == TunnelState.CONNECTING and self.stage:
      statusText = f"Connecting: {self.stage}"
    elif state == TunnelState.FAILED and self.failureText:
      statusText = self.failureText

    if self.notice:
      statusText = self.notice

    ui.sessionStatus.setText(text)
    ui.statusText.setText(statusText)
    ui.statusText.setStyleSheet(f"color: {RED};" if state == TunnelState.FAILED or self.notice else "")
    self._setIndicator(self._dotColour())

  def _dotColour(self):
    if self.notice:
      return RED

    if self.state in BLINKING_STATES:
      return AMBER if self.blinkOn else "#6e4d10"

    return STATE_COLOURS[self.state]

  def _setIndicator(self, colour):
    style = f"background-color: {colour}; border-radius: 4px;"

    self.ui.statusIndicator.setStyleSheet(style)
    self.ui.statusBarIndicator.setStyleSheet(style)

  def _blinkStep(self):
    self.blinkOn = not self.blinkOn
    self._setIndicator(self._dotColour())

  def _tickClock(self):
    if self.connectedAt is not None:
      self.ui.sessionTimer.setText(formatElapsed(time.monotonic() - self.connectedAt))

  def _onStage(self, text):
    self.stage = text

    if self.state == TunnelState.CONNECTING:
      self._showStatus()

  def _onInfo(self, info):
    # a late event of an ended session must not repaint the dimmed values
    if self.state not in LIVE_STATES:
      return

    ui = self.ui

    ui.localIp.setText(info.get("localIp") or EMPTY_VALUE)
    ui.serverIp.setText(info.get("serverIp") or EMPTY_VALUE)
    ui.ipsecInfo.setText(info.get("ipsec") or EMPTY_VALUE)
    ui.pppInfo.setText(info.get("ppp") or EMPTY_VALUE)

  def _onTraffic(self, down, up):
    if self.state == TunnelState.CONNECTED:
      self._showTraffic(down, up)

  def _showTraffic(self, down, up):
    ui = self.ui

    ui.downloadSpeed.setText(formatSpeed(down))
    ui.uploadSpeed.setText(formatSpeed(up))
    ui.downloadBar.setValue(barValue(down))
    ui.uploadBar.setValue(barValue(up))

  def _appendLog(self, text):
    # the tunnel never emits secrets, so a line can go to the file as it is
    self.ui.logPanel.appendPlainText(text)
    logger.info(text)

  # -------------------------------------------------------------------------- #
  def _setInvalid(self, widget, invalid):
    widget.setProperty("invalid", "true" if invalid else "false")
    widget.style().unpolish(widget)
    widget.style().polish(widget)

  def _markInvalid(self, fieldName):
    # a failed() field name maps to the inputs it marks
    fields = {
      "credentials": ("username_input", "password_input"),
      "username": ("username_input",),
      "password": ("password_input",),
      "psk": ("psk_input",),
      "server": ("server_input",)
    }

    for name in fields.get(fieldName, ()):
      self._setInvalid(getattr(self.ui, name), True)

  def _clearInvalid(self):
    for name in INPUT_NAMES:
      if getattr(self.ui, name).property("invalid") == "true":
        self._setInvalid(getattr(self.ui, name), False)

  def _onFailed(self, message, field):
    self.failureText = message

    self._clearInvalid()
    self._markInvalid(field)

    if self.state == TunnelState.FAILED:
      self._showStatus()

  # -------------------------------------------------------------------------- #
  def _currentStored(self):
    return self.profiles[self.shownIndex] if 0 <= self.shownIndex < len(self.profiles) else None

  def _formProfile(self):
    ui = self.ui
    # advanced keys of the stored profile ride along, the form only edits the visible ones
    base = self._currentStored() or Profile()

    return replace(
      base,

      name = base.name or ui.profile_combo.currentText(),
      server = ui.server_input.text().strip(),
      username = ui.username_input.text(),
      password = ui.password_input.text(),
      psk = ui.psk_input.text(),
      ipsecEnabled = ui.ipsec_checkbox.isChecked(),
      routeAll = ui.routeAll_checkbox.isChecked(),
      remember = ui.remember_checkbox.isChecked()
    )

  def _loadForm(self, profile):
    ui = self.ui
    self.loading = True

    try:
      ui.server_input.setText(profile.server)
      ui.username_input.setText(profile.username)
      ui.password_input.setText(profile.password if profile.remember else "")
      ui.psk_input.setText(profile.psk if profile.remember else "")
      ui.ipsec_checkbox.setChecked(profile.ipsecEnabled)
      ui.routeAll_checkbox.setChecked(profile.routeAll)
      ui.remember_checkbox.setChecked(profile.remember)
    finally:
      self.loading = False

    self._clearInvalid()
    self._refreshEnabled()
    self._refreshDirty()

  def _loadProfileList(self):
    self.profiles = list(loadProfiles()[0])

    if not self.profiles:
      self.profiles = [Profile(name = NEW_PROFILE_NAME)]
      self.drafts = {NEW_PROFILE_NAME}

    names = [profile.name for profile in self.profiles]
    self._fillCombo(names.index(self.settings.lastProfile) if self.settings.lastProfile in names else 0)

  def _fillCombo(self, index):
    combo = self.ui.profile_combo

    combo.blockSignals(True)
    combo.clear()
    combo.addItems([profile.name for profile in self.profiles])
    combo.blockSignals(False)
    self._showIndex(index)

  def _showIndex(self, index):
    # moves the combo and the form without triggering the unsaved-changes question
    combo = self.ui.profile_combo

    combo.blockSignals(True)
    combo.setCurrentIndex(index)
    combo.blockSignals(False)

    self.shownIndex = index

    self._loadForm(self.profiles[index])

  def _askSaveChanges(self, window, name = ""):
    dialog = ChoiceDialog(window, APP_NAME, f"Save the changes to “{name}”?", "The profile has edits that were not saved", ("SAVE", "DISCARD", "CANCEL"), "SAVE")

    return dialog.ask()

  def _askDelete(self, window, name):
    dialog = ChoiceDialog(window, APP_NAME, f"Delete profile “{name}”?", "The saved server, user name and keys of this profile are removed. This cannot be undone", ("DELETE", "CANCEL"), "CANCEL", "DELETE")

    return dialog.ask() == "DELETE"

  def _confirmLeave(self):
    # return whether the form may be replaced: nothing to lose, saved, or discarded on purpose
    if not self._isDirty():
      return True

    answer = self._askSaveChanges(self.window, self.profiles[self.shownIndex].name if 0 <= self.shownIndex < len(self.profiles) else "")

    if answer == "SAVE":
      self.saveProfile()

      return not self._isDirty()

    return answer == "DISCARD"

  def _onProfileSelected(self, index):
    if index == self.shownIndex or not 0 <= index < len(self.profiles):
      return

    if self._confirmLeave():
      self._showIndex(index)
      return

    # cancel: only the combo goes back, the edited form stays as it is
    self.ui.profile_combo.blockSignals(True)
    self.ui.profile_combo.setCurrentIndex(self.shownIndex)
    self.ui.profile_combo.blockSignals(False)

  def newProfile(self):
    if not self._confirmLeave():
      return

    name = uniqueName(NEW_PROFILE_NAME, {profile.name for profile in self.profiles})

    self.profiles.append(Profile(name = name))
    self.drafts.add(name)
    self.ui.profile_combo.addItem(name)
    self._showIndex(len(self.profiles) - 1)

  def _persist(self):
    # drafts never reach the disk before their first save
    return saveProfiles([profile for profile in self.profiles if profile.name not in self.drafts])

  def saveProfile(self):
    index = self.shownIndex

    if self.state not in EDITABLE_STATES or not 0 <= index < len(self.profiles):
      return

    previous = self.profiles[index]
    profile, wasDraft = self._formProfile(), previous.name in self.drafts

    # a placeholder name gives way to the server host on the first save
    if re.fullmatch(rf"{re.escape(NEW_PROFILE_NAME)}( \(\d+\))?", profile.name) and profile.server:
      profile.name = uniqueName(profile.server, {other.name for other in self.profiles if other is not previous})

    stored = profile if profile.remember else replace(profile, password = "", psk = "")
    self.profiles[index] = stored

    self.drafts.discard(previous.name)

    if not self._persist():
      self.profiles[index] = previous

      if wasDraft:
        self.drafts.add(previous.name)

      self._appendLog("the profile could not be saved")
      return

    self.ui.profile_combo.setItemText(index, stored.name)

    self.settings.lastProfile = stored.name

    saveSettings(self.settings)
    self._refreshDirty()

  def deleteProfile(self):
    index = self.shownIndex

    if not 0 <= index < len(self.profiles):
      return

    name = self.profiles[index].name

    if not self._askDelete(self.window, name):
      return

    wasDraft = name in self.drafts

    del self.profiles[index]
    self.drafts.discard(name)

    if not self.profiles:
      self.profiles = [Profile(name = NEW_PROFILE_NAME)]
      self.drafts = {NEW_PROFILE_NAME}

    if not wasDraft and not self._persist():
      self._appendLog("the profile list could not be saved")

    self._fillCombo(min(index, len(self.profiles) - 1))

  def _isDirty(self):
    stored = self._currentStored()

    return stored is not None and snapshotOf(self._formProfile()) != snapshotOf(stored)

  def _refreshDirty(self):
    button, dirty = self.ui.saveProfile_button, self._isDirty()

    button.setIcon(QtGui.QIcon(":/icons/icons/save_dirty.png" if dirty else ":/icons/icons/save.png"))
    button.setEnabled(dirty and self.state in EDITABLE_STATES)

  def _clearNotice(self):
    if self.notice:
      self.notice = ""
      self._showStatus()

  def _onEdited(self, widget):
    if not self.loading:
      self._clearNotice()
      self._setInvalid(widget, False)
      self._refreshDirty()

  def _onToggled(self, checked):
    if not self.loading:
      self._clearNotice()
      self._refreshEnabled()
      self._refreshDirty()

  # -------------------------------------------------------------------------- #
  def _onConnect(self):
    self._clearNotice()

    if not self.dllPath.is_file():
      message = "wintun.dll is missing: reinstall AURA"

      self._appendLog(message)

      self.notice = message

      self._showStatus()

      return

    profile = self._formProfile()

    # an unsaved form connects as it stands. the last-profile choice only follows saved names
    if profile.name not in self.drafts:
      self.settings.lastProfile = profile.name
      saveSettings(self.settings)

    self.session.connectTo(profile)

  def shutDown(self):
    # a busy tunnel is torn down before the process exits, with events pumped so the window repaints.
    # a second close request during that wait must not start a second shutdown
    if self.closing:
      return

    self.closing = True

    if self.session.isBusy():
      self.window.setEnabled(False)
      self.ui.statusText.setText("Disconnecting…")

    self.session.disconnect()

    # a teardown (route, dns and adapter removal) can run that long after a cancel
    deadline = time.monotonic() + 40.0

    while not self.session.wait(0.05):
      QtWidgets.QApplication.processEvents()

      if time.monotonic() >= deadline:
        logger.warning("the tunnel did not end within the close timeout")
        self._detachSession()

        break

    QtWidgets.QApplication.processEvents()
    self.blinkTimer.stop()
    self.clockTimer.stop()

  def _detachSession(self):
    # the worker may still emit while the process leaves. nothing may reach a destroyed widget
    self.session.blockSignals(True)

    for signal, slot in self.links:
      try:
        signal.disconnect(slot)
      except TypeError:
        pass

# ---------------------------------------------------------------------------- #

# FINISH --------------------------------------------------------------------- #
def projectRoot():
  # the folder of the original exe when frozen, otherwise the folder of this file
  return exeDirectory() if isFrozen() else Path(__file__).resolve().parent

def configureScaling():
  # the scale variables must be set before QApplication exists to take effect
  environ["QT_SCALE_FACTOR"] = "1.2"
  environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
  environ["QT_SCALE_FACTOR_ROUNDING_POLICY"] = "PassThrough"

  for name in ("AA_Use96Dpi", "AA_UseHighDpiPixmaps", "AA_EnableHighDpiScaling"):
    if hasattr(QtCore.Qt, name):
      QtWidgets.QApplication.setAttribute(getattr(QtCore.Qt, name), True)

def createSingleton():
  # returns the mutex handle, or None when another instance already owns it
  kernel32 = WinDLL("kernel32", use_last_error = True)

  kernel32.CreateMutexW.restype = c_void_p

  handle = kernel32.CreateMutexW(None, False, f"Global\\{APP_NAME}-singleton")

  # 183 is ERROR_ALREADY_EXISTS
  return None if get_last_error() == 183 else handle

def main():
  # profiles.json, settings.json, recovery.json and the logs are relative to the working directory
  chdir(projectRoot())

  configureScaling()

  app = QtWidgets.QApplication(argv)
  mutex = createSingleton()

  if mutex is None:
    QtWidgets.QMessageBox.critical(None, "ERROR", "The program is already running!")

    sysExit(0)

  # modules.admin imports the logger, so it comes after the chdir and the singleton
  # check. a second instance leaves without a logs/
  from modules.admin import isAdmin, relaunchAsAdmin

  if not isAdmin():
    # release the mutex first so the elevated instance can take it
    WinDLL("kernel32").CloseHandle(c_void_p(mutex))
    relaunchAsAdmin()

    sysExit(0)

  app.setApplicationName(APP_NAME)
  app.setApplicationDisplayName(APP_NAME)
  app.setApplicationVersion(APP_VERSION)

  loadRuntime()
  sweepAtStartup()

  controller = Controller()

  controller.window.show()

  sysExit(app.exec_())

if __name__ == "__main__":
  main()
# ---------------------------------------------------------------------------- #
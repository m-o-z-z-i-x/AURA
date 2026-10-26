# ---------------------------------------------------------------------------- #
# DESCRIPTION: user choices carried over between launches
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
import json

from pathlib import Path
from dataclasses import dataclass, asdict, fields
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
SETTINGS_PATH = Path("./settings.json")

@dataclass
class UserSettings:
  # profiles are remembered by name, never by position, since the list changes as the user edits it
  lastProfile: str = ""

def loadSettings():
  # an unreadable or foreign file yields the defaults, so a damaged settings.json never blocks the start
  settings = UserSettings()

  try:
    stored = json.loads(SETTINGS_PATH.read_text(encoding = "utf-8"))
  except Exception:
    return settings

  if not isinstance(stored, dict):
    return settings

  for field in fields(UserSettings):
    if isinstance(value := stored.get(field.name), type(getattr(settings, field.name))):
      setattr(settings, field.name, value)

  return settings

def saveSettings(settings):
  # return success instead of raising, a failed save must not take the window down
  try:
    SETTINGS_PATH.write_text(json.dumps(asdict(settings), indent = 2), encoding = "utf-8")

    return True
  except Exception:
    return False
# ---------------------------------------------------------------------------- #
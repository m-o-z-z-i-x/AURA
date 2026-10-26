# ---------------------------------------------------------------------------- #
# DESCRIPTION: custom qt widgets and dialogs: the promoted profile combo and the themed choice dialog
# ---------------------------------------------------------------------------- #

# DEPENDENCIES --------------------------------------------------------------- #
from PyQt5 import QtCore, QtWidgets
# ---------------------------------------------------------------------------- #

# LOGIC ---------------------------------------------------------------------- #
DIALOG_WIDTH = 360
DIALOG_MARGIN = 10
DIALOG_GAP = 6

class ProfileComboBox(QtWidgets.QComboBox):
  def showPopup(self):
    # the popup is as narrow as the closed combo, which cuts long profile names. widen it to the
    # longest one, plus the scrollbar when the list is tall enough to show one
    view = self.view()
    scrollbarWidth = view.verticalScrollBar().sizeHint().width() if self.count() > self.maxVisibleItems() else 0

    view.setMinimumWidth(max(self.width(), view.sizeHintForColumn(0) + view.frameWidth() * 2 + scrollbarWidth))

    super().showPopup()

class ChoiceDialog(QtWidgets.QDialog):
  # a themed question with one button per caption. the last caption is the cancel answer,
  # which Escape and the close button give too
  def __init__(self, parent, title, text, detail, captions, default, danger = None):
    super().__init__(parent, QtCore.Qt.Dialog | QtCore.Qt.WindowTitleHint | QtCore.Qt.WindowCloseButtonHint)
    self.setObjectName("choiceDialog")
    self.setWindowTitle(title)
    self.setModal(True)
    self.setFixedWidth(DIALOG_WIDTH)

    self.answer = captions[-1]

    layout = QtWidgets.QVBoxLayout(self)

    layout.setContentsMargins(DIALOG_MARGIN, DIALOG_MARGIN, DIALOG_MARGIN, DIALOG_MARGIN)
    layout.setSpacing(DIALOG_GAP)

    for name, content in (("dialogMessage", text), ("dialogDetail", detail)):
      label = QtWidgets.QLabel(content)

      label.setObjectName(name)
      label.setWordWrap(True)
      label.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
      layout.addWidget(label)

    layout.addSpacing(DIALOG_MARGIN - DIALOG_GAP)

    row = QtWidgets.QHBoxLayout()

    row.setSpacing(8)
    layout.addLayout(row)

    for caption in captions:
      button = QtWidgets.QPushButton(caption)

      button.setFixedHeight(30)
      button.setCursor(QtCore.Qt.PointingHandCursor)
      button.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
      button.clicked.connect(lambda checked = False, value = caption: self.choose(value))
      row.addWidget(button, 1)

      if caption == default:
        button.setDefault(True)
        button.setFocus()

      if caption == danger:
        button.setProperty("danger", True)
        button.style().unpolish(button)
        button.style().polish(button)

  def choose(self, caption):
    self.answer = caption
    self.accept()

  def ask(self):
    # blocks until answered. a dismissed dialog keeps the cancel answer
    # polish first so the stylesheet fonts count in the size, then centre over the parent
    for widget in (self, *self.findChildren(QtWidgets.QWidget)):
      widget.ensurePolished()

    self.layout().activate()
    self.resize(DIALOG_WIDTH, self.layout().totalHeightForWidth(DIALOG_WIDTH))

    if (parent := self.parentWidget()) is not None:
      self.move(parent.frameGeometry().center() - self.rect().center())

    self.exec_()

    return self.answer
# ---------------------------------------------------------------------------- #
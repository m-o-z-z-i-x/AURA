from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_mainWindow(object):
    def setupUi(self, mainWindow):
        mainWindow.setObjectName("mainWindow")
        mainWindow.resize(620, 480)
        mainWindow.setMinimumSize(QtCore.QSize(620, 480))
        mainWindow.setMaximumSize(QtCore.QSize(620, 480))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        mainWindow.setFont(font)
        mainWindow.setFocusPolicy(QtCore.Qt.NoFocus)
        mainWindow.setContextMenuPolicy(QtCore.Qt.NoContextMenu)
        mainWindow.setWindowTitle("AURA")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/icons/icons/logo.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        mainWindow.setWindowIcon(icon)
        mainWindow.setStyleSheet("/* WINDOW */\n"
"       #mainWidget {\n"
"           background-color: #212121;\n"
"       }\n"
"   /* WINDOW */\n"
"\n"
"   /* TABBAR */\n"
"       QTabBar::Tab {\n"
"           width: 260px;\n"
"           padding: 10px 20px;\n"
"           color: rgba(255, 255, 255, 0.60);\n"
"           border-bottom: 4px solid #212121;\n"
"           text-transform: uppercase;\n"
"           background-color: #303030;\n"
"       }\n"
"\n"
"       QTabBar::Tab:hover {\n"
"           color: rgba(255, 255, 255, 0.87);\n"
"           background-color: #353535;\n"
"       }\n"
"\n"
"       QTabBar::Tab:selected {\n"
"           color: rgba(255, 255, 255, 0.87);\n"
"           background-color: #292929;\n"
"       }\n"
"\n"
"       QTabWidget::pane {\n"
"           border: none;\n"
"           background-color: #292929;\n"
"       }\n"
"   /* TABBAR */\n"
"\n"
"   /* WIDGETS */\n"
"       QPlainTextEdit {\n"
"           padding: 5px;\n"
"           color: rgba(255, 255, 255, 0.60);\n"
"           border: 1px solid #353535;\n"
"           background-color: #303030;\n"
"       }\n"
"\n"
"       QPlainTextEdit:hover {\n"
"           border: 1px solid #393939;\n"
"       }\n"
"\n"
"       QLineEdit {\n"
"           padding: 0 8px;\n"
"           color: rgba(255, 255, 255, 0.87);\n"
"           border: 1px solid #353535;\n"
"           background-color: #303030;\n"
"       }\n"
"\n"
"       QLineEdit:hover {\n"
"           border: 1px solid #393939;\n"
"       }\n"
"\n"
"       QLineEdit:focus {\n"
"           border: 1px solid #4a4a4a;\n"
"       }\n"
"\n"
"       QLineEdit:disabled {\n"
"           color: rgba(255, 255, 255, 0.30);\n"
"           background-color: #363636;\n"
"       }\n"
"\n"
"       QLineEdit[invalid=\"true\"] {\n"
"           border: 1px solid #c74040;\n"
"       }\n"
"\n"
"       QLabel {\n"
"           color: rgba(255, 255, 255, 0.60);\n"
"       }\n"
"\n"
"       QLabel:disabled {\n"
"           color: rgba(255, 255, 255, 0.30);\n"
"       }\n"
"\n"
"       QPushButton {\n"
"           color: rgba(255, 255, 255, 0.60);\n"
"           border: 1px solid #353535;\n"
"           background-color: #303030;\n"
"       }\n"
"\n"
"       QPushButton:hover {\n"
"           color: rgba(255, 255, 255, 0.87);\n"
"           background-color: #393939;\n"
"       }\n"
"\n"
"       QPushButton:pressed {\n"
"           color: rgba(255, 255, 255, 0.87);\n"
"           border: 1px solid #2f2f2f;\n"
"           background-color: #2a2a2a;\n"
"       }\n"
"\n"
"       QPushButton:disabled {\n"
"           color: rgba(255, 255, 255, 0.30);\n"
"           background-color: #363636;\n"
"       }\n"
"\n"
"       QCheckBox {\n"
"           color: rgba(255, 255, 255, 0.60);\n"
"       }\n"
"\n"
"       QCheckBox:disabled {\n"
"           color: rgba(255, 255, 255, 0.30);\n"
"       }\n"
"\n"
"       QCheckBox::indicator {\n"
"           width: 12px;\n"
"           height: 12px;\n"
"           background-color: rgba(255, 255, 255, 0.30);\n"
"       }\n"
"\n"
"       QCheckBox::indicator:checked {\n"
"           background-color: rgba(255, 255, 255, 0.60);\n"
"       }\n"
"\n"
"       QCheckBox::indicator:disabled {\n"
"           background-color: rgba(255, 255, 255, 0.15);\n"
"       }\n"
"\n"
"       QCheckBox::indicator:checked:disabled {\n"
"           background-color: rgba(255, 255, 255, 0.30);\n"
"       }\n"
"\n"
"       QComboBox {\n"
"           padding: 0 5px;\n"
"           color: rgba(255, 255, 255, 0.60);\n"
"           border: 1px solid #353535;\n"
"           background-color: #303030;\n"
"       }\n"
"\n"
"       QComboBox:hover {\n"
"           border: 1px solid #393939;\n"
"       }\n"
"\n"
"       QComboBox:disabled {\n"
"           color: rgba(255, 255, 255, 0.30);\n"
"           background-color: #363636;\n"
"       }\n"
"\n"
"       QComboBox::drop-down {\n"
"           width: 18px;\n"
"           border: none;\n"
"       }\n"
"\n"
"       QComboBox::down-arrow {\n"
"           width: 10px;\n"
"           height: 10px;\n"
"           image: url(:/icons/icons/arrow_down.png);\n"
"       }\n"
"\n"
"       QComboBox::down-arrow:on {\n"
"           image: url(:/icons/icons/arrow_up.png);\n"
"       }\n"
"\n"
"       QComboBox QAbstractItemView {\n"
"           color: rgba(255, 255, 255, 0.60);\n"
"           border: 1px solid #353535;\n"
"           background-color: #393939;\n"
"           selection-color: rgba(255, 255, 255, 0.87);\n"
"           selection-background-color: #424242;\n"
"       }\n"
"\n"
"       QProgressBar {\n"
"           border: 1px solid #353535;\n"
"           background-color: #1c1c1c;\n"
"       }\n"
"\n"
"       QProgressBar::chunk {\n"
"           width: 5px;\n"
"           margin: 1px;\n"
"           background-color: #5a5a5a;\n"
"       }\n"
"\n"
"       QProgressBar::chunk:disabled {\n"
"           background-color: transparent;\n"
"       }\n"
"\n"
"       QDialog {\n"
"           background-color: #292929;\n"
"       }\n"
"\n"
"       #dialogMessage {\n"
"           font-size: 9pt;\n"
"           color: rgba(255, 255, 255, 0.87);\n"
"       }\n"
"\n"
"       #dialogDetail {\n"
"           color: rgba(255, 255, 255, 0.60);\n"
"       }\n"
"\n"
"       #choiceDialog QPushButton:default {\n"
"           border: 1px solid #4a4a4a;\n"
"       }\n"
"\n"
"       #choiceDialog QPushButton[danger=\"true\"] {\n"
"           color: #e08a8a;\n"
"           border: 1px solid #4a3030;\n"
"       }\n"
"\n"
"       #choiceDialog QPushButton[danger=\"true\"]:hover {\n"
"           color: #f0a0a0;\n"
"           border: 1px solid #6a3a3a;\n"
"           background-color: #3a2f2f;\n"
"       }\n"
"\n"
"       QScrollBar:vertical {\n"
"           width: 20px;\n"
"           margin: 5px;\n"
"           border: none;\n"
"           background-color: #393939;\n"
"       }\n"
"\n"
"       QScrollBar::handle:vertical {\n"
"           border: none;\n"
"           background-color: #444;\n"
"       }\n"
"\n"
"       QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {\n"
"           background-color: none;\n"
"       }\n"
"\n"
"       QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {\n"
"           background-color: none;\n"
"       }\n"
"   /* WIDGETS */\n"
"\n"
"   /* MAIN-TAB */\n"
"       #mainTab {\n"
"           background-color: #292929;\n"
"       }\n"
"\n"
"       #connectionPanel, #sessionPanel, #statusBar {\n"
"           border: 1px solid #353535;\n"
"           background-color: #2b2b2b;\n"
"       }\n"
"\n"
"       #logPanel {\n"
"           padding: 3px 8px;\n"
"           background-color: #2b2b2b;\n"
"       }\n"
"\n"
"       #sessionLine_1, #sessionLine_2, #sessionLine_3, #sessionLine_4 {\n"
"           border: none;\n"
"           background-color: #353535;\n"
"       }\n"
"\n"
"       #sessionCaption {\n"
"           color: rgba(255, 255, 255, 0.30);\n"
"       }\n"
"\n"
"       #sessionStatus, #sessionTimer, #localIp, #serverIp, #ipsecInfo, #pppInfo, #downloadSpeed, #uploadSpeed {\n"
"           color: rgba(255, 255, 255, 0.87);\n"
"       }\n"
"\n"
"       #sessionStatus:disabled, #sessionTimer:disabled, #localIp:disabled, #serverIp:disabled, #ipsecInfo:disabled, #pppInfo:disabled, #downloadSpeed:disabled, #uploadSpeed:disabled {\n"
"           color: rgba(255, 255, 255, 0.30);\n"
"       }\n"
"\n"
"       #statusIndicator, #statusBarIndicator {\n"
"           border-radius: 4px;\n"
"           background-color: rgba(255, 255, 255, 0.15);\n"
"       }\n"
"   /* MAIN-TAB */\n"
"\n"
"   /* ABOUT-TAB */\n"
"       #aboutTab {\n"
"           background-color: #292929;\n"
"       }\n"
"\n"
"       #programIcon {\n"
"           width: 100%;\n"
"           height: 100%;\n"
"           background-image: url(:/icons/icons/logo.png);\n"
"           background-repeat: norepeat;\n"
"           background-position: 50% 50%;\n"
"       }\n"
"   /* ABOUT-TAB */")
        mainWindow.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        mainWindow.setIconSize(QtCore.QSize(14, 14))
        mainWindow.setAnimated(False)
        self.mainWidget = QtWidgets.QWidget(mainWindow)
        self.mainWidget.setObjectName("mainWidget")
        self.tabWidget = QtWidgets.QTabWidget(self.mainWidget)
        self.tabWidget.setGeometry(QtCore.QRect(10, 10, 600, 460))
        font = QtGui.QFont()
        font.setFamily("MS Shell Dlg 2")
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.tabWidget.setFont(font)
        self.tabWidget.setFocusPolicy(QtCore.Qt.NoFocus)
        self.tabWidget.setContextMenuPolicy(QtCore.Qt.NoContextMenu)
        self.tabWidget.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.tabWidget.setIconSize(QtCore.QSize(14, 14))
        self.tabWidget.setUsesScrollButtons(False)
        self.tabWidget.setObjectName("tabWidget")
        self.mainTab = QtWidgets.QWidget()
        self.mainTab.setObjectName("mainTab")
        self.connectionPanel = QtWidgets.QWidget(self.mainTab)
        self.connectionPanel.setGeometry(QtCore.QRect(8, 8, 288, 240))
        self.connectionPanel.setObjectName("connectionPanel")
        self.profile_combo = ProfileComboBox(self.connectionPanel)
        self.profile_combo.setGeometry(QtCore.QRect(9, 9, 180, 26))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.profile_combo.setFont(font)
        self.profile_combo.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.profile_combo.setFocusPolicy(QtCore.Qt.NoFocus)
        self.profile_combo.setToolTip("Saved connection profiles")
        self.profile_combo.setObjectName("profile_combo")
        self.newProfile_button = QtWidgets.QPushButton(self.connectionPanel)
        self.newProfile_button.setGeometry(QtCore.QRect(193, 9, 26, 26))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.newProfile_button.setFont(font)
        self.newProfile_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.newProfile_button.setFocusPolicy(QtCore.Qt.NoFocus)
        self.newProfile_button.setToolTip("New profile")
        self.newProfile_button.setText("")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/icons/icons/new.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.newProfile_button.setIcon(icon1)
        self.newProfile_button.setIconSize(QtCore.QSize(14, 14))
        self.newProfile_button.setObjectName("newProfile_button")
        self.saveProfile_button = QtWidgets.QPushButton(self.connectionPanel)
        self.saveProfile_button.setGeometry(QtCore.QRect(223, 9, 26, 26))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.saveProfile_button.setFont(font)
        self.saveProfile_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.saveProfile_button.setFocusPolicy(QtCore.Qt.NoFocus)
        self.saveProfile_button.setToolTip("Save profile (Ctrl+S)")
        self.saveProfile_button.setText("")
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/icons/icons/save.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.saveProfile_button.setIcon(icon2)
        self.saveProfile_button.setIconSize(QtCore.QSize(14, 14))
        self.saveProfile_button.setObjectName("saveProfile_button")
        self.deleteProfile_button = QtWidgets.QPushButton(self.connectionPanel)
        self.deleteProfile_button.setGeometry(QtCore.QRect(253, 9, 26, 26))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.deleteProfile_button.setFont(font)
        self.deleteProfile_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.deleteProfile_button.setFocusPolicy(QtCore.Qt.NoFocus)
        self.deleteProfile_button.setToolTip("Delete profile")
        self.deleteProfile_button.setText("")
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(":/icons/icons/delete.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.deleteProfile_button.setIcon(icon3)
        self.deleteProfile_button.setIconSize(QtCore.QSize(14, 14))
        self.deleteProfile_button.setObjectName("deleteProfile_button")
        self.serverLabel = QtWidgets.QLabel(self.connectionPanel)
        self.serverLabel.setGeometry(QtCore.QRect(9, 42, 84, 26))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.serverLabel.setFont(font)
        self.serverLabel.setText("Server")
        self.serverLabel.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.serverLabel.setObjectName("serverLabel")
        self.server_input = QtWidgets.QLineEdit(self.connectionPanel)
        self.server_input.setGeometry(QtCore.QRect(93, 42, 186, 26))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.server_input.setFont(font)
        self.server_input.setToolTip("Address of the L2TP server — host name or IP")
        self.server_input.setPlaceholderText("vpn.example.com")
        self.server_input.setObjectName("server_input")
        self.usernameLabel = QtWidgets.QLabel(self.connectionPanel)
        self.usernameLabel.setGeometry(QtCore.QRect(9, 75, 84, 26))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.usernameLabel.setFont(font)
        self.usernameLabel.setText("Username")
        self.usernameLabel.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.usernameLabel.setObjectName("usernameLabel")
        self.username_input = QtWidgets.QLineEdit(self.connectionPanel)
        self.username_input.setGeometry(QtCore.QRect(93, 75, 186, 26))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.username_input.setFont(font)
        self.username_input.setToolTip("PPP username")
        self.username_input.setPlaceholderText("username")
        self.username_input.setObjectName("username_input")
        self.passwordLabel = QtWidgets.QLabel(self.connectionPanel)
        self.passwordLabel.setGeometry(QtCore.QRect(9, 108, 84, 26))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.passwordLabel.setFont(font)
        self.passwordLabel.setText("Password")
        self.passwordLabel.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.passwordLabel.setObjectName("passwordLabel")
        self.password_input = QtWidgets.QLineEdit(self.connectionPanel)
        self.password_input.setGeometry(QtCore.QRect(93, 108, 186, 26))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.password_input.setFont(font)
        self.password_input.setToolTip("PPP password")
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setPlaceholderText("password")
        self.password_input.setObjectName("password_input")
        self.pskLabel = QtWidgets.QLabel(self.connectionPanel)
        self.pskLabel.setGeometry(QtCore.QRect(9, 141, 84, 26))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.pskLabel.setFont(font)
        self.pskLabel.setText("Pre-shared key")
        self.pskLabel.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.pskLabel.setObjectName("pskLabel")
        self.psk_input = QtWidgets.QLineEdit(self.connectionPanel)
        self.psk_input.setGeometry(QtCore.QRect(93, 141, 186, 26))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.psk_input.setFont(font)
        self.psk_input.setToolTip("IPsec pre-shared key — used only while IPsec is on")
        self.psk_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.psk_input.setPlaceholderText("pre-shared key")
        self.psk_input.setObjectName("psk_input")
        self.optionsRow = QtWidgets.QWidget(self.connectionPanel)
        self.optionsRow.setGeometry(QtCore.QRect(9, 174, 270, 22))
        self.optionsRow.setObjectName("optionsRow")
        self.optionsLayout = QtWidgets.QHBoxLayout(self.optionsRow)
        self.optionsLayout.setContentsMargins(0, 0, 0, 0)
        self.optionsLayout.setSpacing(0)
        self.optionsLayout.setObjectName("optionsLayout")
        self.ipsec_checkbox = QtWidgets.QCheckBox(self.optionsRow)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.ipsec_checkbox.sizePolicy().hasHeightForWidth())
        self.ipsec_checkbox.setSizePolicy(sizePolicy)
        self.ipsec_checkbox.setMinimumSize(QtCore.QSize(0, 22))
        self.ipsec_checkbox.setMaximumSize(QtCore.QSize(16777215, 22))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.ipsec_checkbox.setFont(font)
        self.ipsec_checkbox.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.ipsec_checkbox.setFocusPolicy(QtCore.Qt.NoFocus)
        self.ipsec_checkbox.setToolTip("Wrap L2TP in IPsec — most servers require it")
        self.ipsec_checkbox.setText("IPsec")
        self.ipsec_checkbox.setChecked(True)
        self.ipsec_checkbox.setObjectName("ipsec_checkbox")
        self.optionsLayout.addWidget(self.ipsec_checkbox)
        spacerItem = QtWidgets.QSpacerItem(40, 18, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.optionsLayout.addItem(spacerItem)
        self.routeAll_checkbox = QtWidgets.QCheckBox(self.optionsRow)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.routeAll_checkbox.sizePolicy().hasHeightForWidth())
        self.routeAll_checkbox.setSizePolicy(sizePolicy)
        self.routeAll_checkbox.setMinimumSize(QtCore.QSize(0, 22))
        self.routeAll_checkbox.setMaximumSize(QtCore.QSize(16777215, 22))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.routeAll_checkbox.setFont(font)
        self.routeAll_checkbox.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.routeAll_checkbox.setFocusPolicy(QtCore.Qt.NoFocus)
        self.routeAll_checkbox.setToolTip("Send all traffic through the tunnel; off keeps only the tunnel subnet")
        self.routeAll_checkbox.setText("Route all")
        self.routeAll_checkbox.setChecked(True)
        self.routeAll_checkbox.setObjectName("routeAll_checkbox")
        self.optionsLayout.addWidget(self.routeAll_checkbox)
        spacerItem1 = QtWidgets.QSpacerItem(40, 18, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.optionsLayout.addItem(spacerItem1)
        self.remember_checkbox = QtWidgets.QCheckBox(self.optionsRow)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.remember_checkbox.sizePolicy().hasHeightForWidth())
        self.remember_checkbox.setSizePolicy(sizePolicy)
        self.remember_checkbox.setMinimumSize(QtCore.QSize(0, 22))
        self.remember_checkbox.setMaximumSize(QtCore.QSize(16777215, 22))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.remember_checkbox.setFont(font)
        self.remember_checkbox.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.remember_checkbox.setFocusPolicy(QtCore.Qt.NoFocus)
        self.remember_checkbox.setToolTip("Keep the password and key in the profile, encrypted for this Windows account")
        self.remember_checkbox.setText("Remember")
        self.remember_checkbox.setObjectName("remember_checkbox")
        self.optionsLayout.addWidget(self.remember_checkbox)
        self.connect_button = QtWidgets.QPushButton(self.connectionPanel)
        self.connect_button.setGeometry(QtCore.QRect(9, 202, 131, 30))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.connect_button.setFont(font)
        self.connect_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.connect_button.setFocusPolicy(QtCore.Qt.NoFocus)
        self.connect_button.setToolTip("Connect with the selected profile")
        self.connect_button.setText("CONNECT")
        self.connect_button.setObjectName("connect_button")
        self.disconnect_button = QtWidgets.QPushButton(self.connectionPanel)
        self.disconnect_button.setGeometry(QtCore.QRect(148, 202, 131, 30))
        self.disconnect_button.setEnabled(False)
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.disconnect_button.setFont(font)
        self.disconnect_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.disconnect_button.setFocusPolicy(QtCore.Qt.NoFocus)
        self.disconnect_button.setToolTip("Disconnect, or cancel the attempt in progress")
        self.disconnect_button.setText("DISCONNECT")
        self.disconnect_button.setObjectName("disconnect_button")
        self.sessionPanel = QtWidgets.QWidget(self.mainTab)
        self.sessionPanel.setGeometry(QtCore.QRect(304, 8, 288, 240))
        self.sessionPanel.setObjectName("sessionPanel")
        self.sessionCaption = QtWidgets.QLabel(self.sessionPanel)
        self.sessionCaption.setGeometry(QtCore.QRect(9, 9, 270, 14))
        font = QtGui.QFont()
        font.setPointSize(7)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.sessionCaption.setFont(font)
        self.sessionCaption.setText("SESSION")
        self.sessionCaption.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.sessionCaption.setObjectName("sessionCaption")
        self.statusIndicator = QtWidgets.QLabel(self.sessionPanel)
        self.statusIndicator.setMinimumSize(QtCore.QSize(9, 9))
        self.statusIndicator.setMaximumSize(QtCore.QSize(9, 9))
        self.statusIndicator.setGeometry(QtCore.QRect(9, 40, 9, 9))
        self.statusIndicator.setFocusPolicy(QtCore.Qt.NoFocus)
        self.statusIndicator.setText("")
        self.statusIndicator.setObjectName("statusIndicator")
        self.sessionStatus = QtWidgets.QLabel(self.sessionPanel)
        self.sessionStatus.setGeometry(QtCore.QRect(26, 27, 112, 35))
        font = QtGui.QFont()
        font.setFamily("MS Shell Dlg 2")
        font.setPointSize(9)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.sessionStatus.setFont(font)
        self.sessionStatus.setText("Disconnected")
        self.sessionStatus.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.sessionStatus.setObjectName("sessionStatus")
        self.sessionTimer = QtWidgets.QLabel(self.sessionPanel)
        self.sessionTimer.setGeometry(QtCore.QRect(159, 27, 120, 35))
        font = QtGui.QFont()
        font.setFamily("JetBrains Mono")
        font.setPointSize(14)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.sessionTimer.setFont(font)
        self.sessionTimer.setToolTip("Time since the tunnel came up")
        self.sessionTimer.setText("00:00:00")
        self.sessionTimer.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignVCenter)
        self.sessionTimer.setObjectName("sessionTimer")
        self.sessionLine_1 = QtWidgets.QFrame(self.sessionPanel)
        self.sessionLine_1.setGeometry(QtCore.QRect(9, 61, 270, 1))
        self.sessionLine_1.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.sessionLine_1.setObjectName("sessionLine_1")
        self.localIpLabel = QtWidgets.QLabel(self.sessionPanel)
        self.localIpLabel.setGeometry(QtCore.QRect(9, 62, 80, 23))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.localIpLabel.setFont(font)
        self.localIpLabel.setText("Local IP")
        self.localIpLabel.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.localIpLabel.setObjectName("localIpLabel")
        self.localIp = QtWidgets.QLabel(self.sessionPanel)
        self.localIp.setGeometry(QtCore.QRect(89, 62, 190, 23))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.localIp.setFont(font)
        self.localIp.setToolTip("Address the server assigned to this machine")
        self.localIp.setText("—")
        self.localIp.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignVCenter)
        self.localIp.setObjectName("localIp")
        self.sessionLine_2 = QtWidgets.QFrame(self.sessionPanel)
        self.sessionLine_2.setGeometry(QtCore.QRect(9, 85, 270, 1))
        self.sessionLine_2.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.sessionLine_2.setObjectName("sessionLine_2")
        self.serverIpLabel = QtWidgets.QLabel(self.sessionPanel)
        self.serverIpLabel.setGeometry(QtCore.QRect(9, 86, 80, 23))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.serverIpLabel.setFont(font)
        self.serverIpLabel.setText("Server IP")
        self.serverIpLabel.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.serverIpLabel.setObjectName("serverIpLabel")
        self.serverIp = QtWidgets.QLabel(self.sessionPanel)
        self.serverIp.setGeometry(QtCore.QRect(89, 86, 190, 23))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.serverIp.setFont(font)
        self.serverIp.setToolTip("Resolved address of the server")
        self.serverIp.setText("—")
        self.serverIp.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignVCenter)
        self.serverIp.setObjectName("serverIp")
        self.sessionLine_3 = QtWidgets.QFrame(self.sessionPanel)
        self.sessionLine_3.setGeometry(QtCore.QRect(9, 109, 270, 1))
        self.sessionLine_3.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.sessionLine_3.setObjectName("sessionLine_3")
        self.ipsecInfoLabel = QtWidgets.QLabel(self.sessionPanel)
        self.ipsecInfoLabel.setGeometry(QtCore.QRect(9, 110, 80, 23))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.ipsecInfoLabel.setFont(font)
        self.ipsecInfoLabel.setText("IPsec")
        self.ipsecInfoLabel.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.ipsecInfoLabel.setObjectName("ipsecInfoLabel")
        self.ipsecInfo = QtWidgets.QLabel(self.sessionPanel)
        self.ipsecInfo.setGeometry(QtCore.QRect(89, 110, 190, 23))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.ipsecInfo.setFont(font)
        self.ipsecInfo.setToolTip("Negotiated IPsec parameters")
        self.ipsecInfo.setText("—")
        self.ipsecInfo.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignVCenter)
        self.ipsecInfo.setObjectName("ipsecInfo")
        self.sessionLine_4 = QtWidgets.QFrame(self.sessionPanel)
        self.sessionLine_4.setGeometry(QtCore.QRect(9, 133, 270, 1))
        self.sessionLine_4.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.sessionLine_4.setObjectName("sessionLine_4")
        self.pppInfoLabel = QtWidgets.QLabel(self.sessionPanel)
        self.pppInfoLabel.setGeometry(QtCore.QRect(9, 134, 80, 23))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.pppInfoLabel.setFont(font)
        self.pppInfoLabel.setText("PPP")
        self.pppInfoLabel.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.pppInfoLabel.setObjectName("pppInfoLabel")
        self.pppInfo = QtWidgets.QLabel(self.sessionPanel)
        self.pppInfo.setGeometry(QtCore.QRect(89, 134, 190, 23))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.pppInfo.setFont(font)
        self.pppInfo.setToolTip("Negotiated PPP authentication")
        self.pppInfo.setText("—")
        self.pppInfo.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignVCenter)
        self.pppInfo.setObjectName("pppInfo")
        self.downloadLabel = QtWidgets.QLabel(self.sessionPanel)
        self.downloadLabel.setGeometry(QtCore.QRect(9, 167, 135, 16))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.downloadLabel.setFont(font)
        self.downloadLabel.setText("↓ Download")
        self.downloadLabel.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.downloadLabel.setObjectName("downloadLabel")
        self.downloadSpeed = QtWidgets.QLabel(self.sessionPanel)
        self.downloadSpeed.setGeometry(QtCore.QRect(144, 167, 135, 16))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.downloadSpeed.setFont(font)
        self.downloadSpeed.setToolTip("Download speed")
        self.downloadSpeed.setText("0 B/s")
        self.downloadSpeed.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignVCenter)
        self.downloadSpeed.setObjectName("downloadSpeed")
        self.downloadBar = QtWidgets.QProgressBar(self.sessionPanel)
        self.downloadBar.setGeometry(QtCore.QRect(9, 183, 270, 10))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.downloadBar.setFont(font)
        self.downloadBar.setToolTip("Download speed")
        self.downloadBar.setProperty("value", 0)
        self.downloadBar.setTextVisible(False)
        self.downloadBar.setObjectName("downloadBar")
        self.uploadLabel = QtWidgets.QLabel(self.sessionPanel)
        self.uploadLabel.setGeometry(QtCore.QRect(9, 201, 135, 16))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.uploadLabel.setFont(font)
        self.uploadLabel.setText("↑ Upload")
        self.uploadLabel.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.uploadLabel.setObjectName("uploadLabel")
        self.uploadSpeed = QtWidgets.QLabel(self.sessionPanel)
        self.uploadSpeed.setGeometry(QtCore.QRect(144, 201, 135, 16))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.uploadSpeed.setFont(font)
        self.uploadSpeed.setToolTip("Upload speed")
        self.uploadSpeed.setText("0 B/s")
        self.uploadSpeed.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignVCenter)
        self.uploadSpeed.setObjectName("uploadSpeed")
        self.uploadBar = QtWidgets.QProgressBar(self.sessionPanel)
        self.uploadBar.setGeometry(QtCore.QRect(9, 217, 270, 10))
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.uploadBar.setFont(font)
        self.uploadBar.setToolTip("Upload speed")
        self.uploadBar.setProperty("value", 0)
        self.uploadBar.setTextVisible(False)
        self.uploadBar.setObjectName("uploadBar")
        self.logPanel = QtWidgets.QPlainTextEdit(self.mainTab)
        self.logPanel.setGeometry(QtCore.QRect(8, 256, 584, 120))
        font = QtGui.QFont()
        font.setFamily("JetBrains Mono")
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.logPanel.setFont(font)
        self.logPanel.setFocusPolicy(QtCore.Qt.NoFocus)
        self.logPanel.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.logPanel.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.logPanel.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.logPanel.setUndoRedoEnabled(False)
        self.logPanel.setReadOnly(True)
        self.logPanel.setPlainText("")
        self.logPanel.setTextInteractionFlags(QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.logPanel.setObjectName("logPanel")
        self.statusBar = QtWidgets.QWidget(self.mainTab)
        self.statusBar.setGeometry(QtCore.QRect(8, 384, 584, 28))
        self.statusBar.setObjectName("statusBar")
        self.layoutWidget = QtWidgets.QWidget(self.statusBar)
        self.layoutWidget.setGeometry(QtCore.QRect(8, 1, 568, 26))
        self.layoutWidget.setObjectName("layoutWidget")
        self.infoLayout = QtWidgets.QHBoxLayout(self.layoutWidget)
        self.infoLayout.setContentsMargins(0, 0, 0, 0)
        self.infoLayout.setSpacing(0)
        self.infoLayout.setObjectName("infoLayout")
        self.statusBarIndicator = QtWidgets.QLabel(self.layoutWidget)
        self.statusBarIndicator.setMinimumSize(QtCore.QSize(8, 8))
        self.statusBarIndicator.setMaximumSize(QtCore.QSize(8, 8))
        self.statusBarIndicator.setFocusPolicy(QtCore.Qt.NoFocus)
        self.statusBarIndicator.setText("")
        self.statusBarIndicator.setObjectName("statusBarIndicator")
        self.infoLayout.addWidget(self.statusBarIndicator, 0, QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        spacerItem2 = QtWidgets.QSpacerItem(6, 18, QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Minimum)
        self.infoLayout.addItem(spacerItem2)
        self.statusText = QtWidgets.QLabel(self.layoutWidget)
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.statusText.setFont(font)
        self.statusText.setText("Disconnected")
        self.statusText.setObjectName("statusText")
        self.infoLayout.addWidget(self.statusText)
        spacerItem3 = QtWidgets.QSpacerItem(40, 18, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.infoLayout.addItem(spacerItem3)
        self.adapterLabel = QtWidgets.QLabel(self.layoutWidget)
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.adapterLabel.setFont(font)
        self.adapterLabel.setFocusPolicy(QtCore.Qt.NoFocus)
        self.adapterLabel.setText("Adapter: ")
        self.adapterLabel.setObjectName("adapterLabel")
        self.infoLayout.addWidget(self.adapterLabel)
        self.adapter = QtWidgets.QLabel(self.layoutWidget)
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.adapter.setFont(font)
        self.adapter.setFocusPolicy(QtCore.Qt.NoFocus)
        self.adapter.setToolTip("Virtual network adapter state")
        self.adapter.setText("—")
        self.adapter.setObjectName("adapter")
        self.infoLayout.addWidget(self.adapter)
        self.tabWidget.addTab(self.mainTab, "CONNECT")
        self.aboutTab = QtWidgets.QWidget()
        self.aboutTab.setObjectName("aboutTab")
        self.programIcon = QtWidgets.QGraphicsView(self.aboutTab)
        self.programIcon.setGeometry(QtCore.QRect(250, 115, 100, 100))
        self.programIcon.setFocusPolicy(QtCore.Qt.NoFocus)
        self.programIcon.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.programIcon.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.programIcon.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.programIcon.setObjectName("programIcon")
        self.programName = QtWidgets.QLabel(self.aboutTab)
        self.programName.setGeometry(QtCore.QRect(209, 225, 181, 21))
        font = QtGui.QFont()
        font.setFamily("JetBrains Mono")
        font.setPointSize(14)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.programName.setFont(font)
        self.programName.setText("AURA")
        self.programName.setAlignment(QtCore.Qt.AlignCenter)
        self.programName.setObjectName("programName")
        self.programDescription = QtWidgets.QLabel(self.aboutTab)
        self.programDescription.setGeometry(QtCore.QRect(80, 250, 441, 51))
        font = QtGui.QFont()
        font.setFamily("MS Shell Dlg 2")
        font.setPointSize(9)
        font.setKerning(False)
        font.setStyleStrategy(QtGui.QFont.NoAntialias)
        self.programDescription.setFont(font)
        self.programDescription.setText("")
        self.programDescription.setAlignment(QtCore.Qt.AlignCenter)
        self.programDescription.setWordWrap(True)
        self.programDescription.setObjectName("programDescription")
        self.tabWidget.addTab(self.aboutTab, "About")
        mainWindow.setCentralWidget(self.mainWidget)

        self.retranslateUi(mainWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(mainWindow)
        mainWindow.setTabOrder(self.server_input, self.username_input)
        mainWindow.setTabOrder(self.username_input, self.password_input)
        mainWindow.setTabOrder(self.password_input, self.psk_input)

    def retranslateUi(self, mainWindow):
        pass

from modules.widgets import ProfileComboBox
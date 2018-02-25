# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/modules.ui'
#
# Created by: PyQt4 UI code generator 4.12.1
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_Modules(object):
    def setupUi(self, Modules):
        Modules.setObjectName(_fromUtf8("Modules"))
        Modules.resize(400, 300)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Modules.sizePolicy().hasHeightForWidth())
        Modules.setSizePolicy(sizePolicy)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/hex_page.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        Modules.setWindowIcon(icon)
        Modules.setAlternatingRowColors(True)
        self.useless = QtGui.QWidget(Modules)
        self.useless.setObjectName(_fromUtf8("useless"))

        self.retranslateUi(Modules)
        QtCore.QMetaObject.connectSlotsByName(Modules)

    def retranslateUi(self, Modules):
        Modules.setWindowTitle(_translate("Modules", "Modules", None))
        Modules.headerItem().setText(0, _translate("Modules", "Name", None))
        Modules.headerItem().setText(1, _translate("Modules", "Key", None))
        Modules.headerItem().setText(2, _translate("Modules", "Value", None))
        Modules.headerItem().setText(3, _translate("Modules", "Info", None))
        Modules.headerItem().setText(4, _translate("Modules", "Type", None))

import gui_rc

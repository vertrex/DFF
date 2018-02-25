# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/modulebrowserdialog.ui'
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

class Ui_moduleBrowser(object):
    def setupUi(self, moduleBrowser):
        moduleBrowser.setObjectName(_fromUtf8("moduleBrowser"))
        moduleBrowser.resize(572, 272)
        self.verticalLayout_3 = QtGui.QVBoxLayout(moduleBrowser)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.verticalLayout_2 = QtGui.QVBoxLayout()
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.lcontainer = QtGui.QVBoxLayout()
        self.lcontainer.setObjectName(_fromUtf8("lcontainer"))
        self.verticalLayout_2.addLayout(self.lcontainer)
        self.buttonBox = QtGui.QDialogButtonBox(moduleBrowser)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.verticalLayout_2.addWidget(self.buttonBox)
        self.verticalLayout_3.addLayout(self.verticalLayout_2)

        self.retranslateUi(moduleBrowser)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), moduleBrowser.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), moduleBrowser.reject)
        QtCore.QMetaObject.connectSlotsByName(moduleBrowser)

    def retranslateUi(self, moduleBrowser):
        moduleBrowser.setWindowTitle(_translate("moduleBrowser", "Module browser", None))

import gui_rc

# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/errors.ui'
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

class Ui_Errors(object):
    def setupUi(self, Errors):
        Errors.setObjectName(_fromUtf8("Errors"))
        Errors.resize(400, 300)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Errors.sizePolicy().hasHeightForWidth())
        Errors.setSizePolicy(sizePolicy)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/bug.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        Errors.setWindowIcon(icon)

        self.retranslateUi(Errors)
        QtCore.QMetaObject.connectSlotsByName(Errors)

    def retranslateUi(self, Errors):
        Errors.setWindowTitle(_translate("Errors", "Errors", None))

import gui_rc

# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/filter_only.ui'
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

class Ui_filterOnly(object):
    def setupUi(self, filterOnly):
        filterOnly.setObjectName(_fromUtf8("filterOnly"))
        filterOnly.resize(640, 45)
        self.onlyCombo = QtGui.QComboBox(filterOnly)
        self.onlyCombo.setGeometry(QtCore.QRect(9, 9, 85, 31))
        self.onlyCombo.setObjectName(_fromUtf8("onlyCombo"))
        self.onlyCombo.addItem(_fromUtf8(""))
        self.onlyCombo.addItem(_fromUtf8(""))

        self.retranslateUi(filterOnly)
        QtCore.QMetaObject.connectSlotsByName(filterOnly)

    def retranslateUi(self, filterOnly):
        filterOnly.setWindowTitle(_translate("filterOnly", "Form", None))
        self.onlyCombo.setItemText(0, _translate("filterOnly", "True", None))
        self.onlyCombo.setItemText(1, _translate("filterOnly", "False", None))


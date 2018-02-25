# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/filter_matchmode.ui'
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

class Ui_filterMatchMode(object):
    def setupUi(self, filterMatchMode):
        filterMatchMode.setObjectName(_fromUtf8("filterMatchMode"))
        filterMatchMode.resize(640, 45)
        self.matchModeCombo = QtGui.QComboBox(filterMatchMode)
        self.matchModeCombo.setGeometry(QtCore.QRect(9, 9, 124, 27))
        self.matchModeCombo.setObjectName(_fromUtf8("matchModeCombo"))
        self.matchModeCombo.addItem(_fromUtf8(""))
        self.matchModeCombo.addItem(_fromUtf8(""))
        self.matchModeCombo.addItem(_fromUtf8(""))
        self.matchModeCombo.addItem(_fromUtf8(""))
        self.casse = QtGui.QCheckBox(filterMatchMode)
        self.casse.setGeometry(QtCore.QRect(150, 10, 131, 22))
        self.casse.setObjectName(_fromUtf8("casse"))

        self.retranslateUi(filterMatchMode)
        QtCore.QMetaObject.connectSlotsByName(filterMatchMode)

    def retranslateUi(self, filterMatchMode):
        filterMatchMode.setWindowTitle(_translate("filterMatchMode", "Form", None))
        self.matchModeCombo.setItemText(0, _translate("filterMatchMode", "Wildcard", None))
        self.matchModeCombo.setItemText(1, _translate("filterMatchMode", "Reg-exp", None))
        self.matchModeCombo.setItemText(2, _translate("filterMatchMode", "Fuzzy", None))
        self.matchModeCombo.setItemText(3, _translate("filterMatchMode", "Fixed", None))
        self.casse.setText(_translate("filterMatchMode", "Case sensitive", None))


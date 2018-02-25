# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/filter_conjunction.ui'
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

class Ui_filterConjunction(object):
    def setupUi(self, filterConjunction):
        filterConjunction.setObjectName(_fromUtf8("filterConjunction"))
        filterConjunction.resize(640, 45)
        self.conjunctionCombo = QtGui.QComboBox(filterConjunction)
        self.conjunctionCombo.setGeometry(QtCore.QRect(9, 9, 85, 31))
        self.conjunctionCombo.setObjectName(_fromUtf8("conjunctionCombo"))
        self.conjunctionCombo.addItem(_fromUtf8(""))
        self.conjunctionCombo.addItem(_fromUtf8(""))
        self.conjunctionCombo.addItem(_fromUtf8(""))
        self.conjunctionCombo.addItem(_fromUtf8(""))

        self.retranslateUi(filterConjunction)
        QtCore.QMetaObject.connectSlotsByName(filterConjunction)

    def retranslateUi(self, filterConjunction):
        filterConjunction.setWindowTitle(_translate("filterConjunction", "Form", None))
        self.conjunctionCombo.setItemText(0, _translate("filterConjunction", "And", None))
        self.conjunctionCombo.setItemText(1, _translate("filterConjunction", "And not", None))
        self.conjunctionCombo.setItemText(2, _translate("filterConjunction", "Or", None))
        self.conjunctionCombo.setItemText(3, _translate("filterConjunction", "Or not", None))


# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/filter_attributes.ui'
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

class Ui_filterAttributes(object):
    def setupUi(self, filterAttributes):
        filterAttributes.setObjectName(_fromUtf8("filterAttributes"))
        filterAttributes.resize(640, 45)
        self.key = QtGui.QLineEdit(filterAttributes)
        self.key.setGeometry(QtCore.QRect(20, 10, 113, 27))
        self.key.setObjectName(_fromUtf8("key"))
        self.value = QtGui.QLineEdit(filterAttributes)
        self.value.setGeometry(QtCore.QRect(160, 10, 113, 27))
        self.value.setObjectName(_fromUtf8("value"))

        self.retranslateUi(filterAttributes)
        QtCore.QMetaObject.connectSlotsByName(filterAttributes)

    def retranslateUi(self, filterAttributes):
        filterAttributes.setWindowTitle(_translate("filterAttributes", "Form", None))


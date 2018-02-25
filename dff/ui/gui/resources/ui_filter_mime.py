# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/filter_mime.ui'
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

class Ui_filterMime(object):
    def setupUi(self, filterMime):
        filterMime.setObjectName(_fromUtf8("filterMime"))
        filterMime.resize(640, 45)
        self.content = QtGui.QLineEdit(filterMime)
        self.content.setGeometry(QtCore.QRect(20, 10, 113, 27))
        self.content.setObjectName(_fromUtf8("content"))
        self.selectButton = QtGui.QPushButton(filterMime)
        self.selectButton.setGeometry(QtCore.QRect(160, 10, 90, 27))
        self.selectButton.setObjectName(_fromUtf8("selectButton"))

        self.retranslateUi(filterMime)
        QtCore.QMetaObject.connectSlotsByName(filterMime)

    def retranslateUi(self, filterMime):
        filterMime.setWindowTitle(_translate("filterMime", "Form", None))
        self.selectButton.setText(_translate("filterMime", "Select ...", None))


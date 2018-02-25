# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/filter_dico.ui'
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

class Ui_filterDico(object):
    def setupUi(self, filterDico):
        filterDico.setObjectName(_fromUtf8("filterDico"))
        filterDico.resize(631, 50)
        self.dicoPath = QtGui.QLineEdit(filterDico)
        self.dicoPath.setGeometry(QtCore.QRect(20, 10, 341, 27))
        self.dicoPath.setReadOnly(True)
        self.dicoPath.setObjectName(_fromUtf8("dicoPath"))
        self.dicoManager = QtGui.QToolButton(filterDico)
        self.dicoManager.setGeometry(QtCore.QRect(370, 10, 31, 31))
        self.dicoManager.setText(_fromUtf8(""))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/add_dico")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.dicoManager.setIcon(icon)
        self.dicoManager.setObjectName(_fromUtf8("dicoManager"))
        self.dicoType = QtGui.QComboBox(filterDico)
        self.dicoType.setGeometry(QtCore.QRect(410, 10, 71, 27))
        self.dicoType.setObjectName(_fromUtf8("dicoType"))
        self.dicoType.addItem(_fromUtf8(""))
        self.dicoType.addItem(_fromUtf8(""))
        self.dicoMatch = QtGui.QComboBox(filterDico)
        self.dicoMatch.setGeometry(QtCore.QRect(500, 10, 71, 27))
        self.dicoMatch.setObjectName(_fromUtf8("dicoMatch"))
        self.dicoMatch.addItem(_fromUtf8(""))
        self.dicoMatch.addItem(_fromUtf8(""))
        self.dicoMatch.addItem(_fromUtf8(""))

        self.retranslateUi(filterDico)
        QtCore.QMetaObject.connectSlotsByName(filterDico)

    def retranslateUi(self, filterDico):
        filterDico.setWindowTitle(_translate("filterDico", "Form", None))
        self.dicoType.setItemText(0, _translate("filterDico", "Name", None))
        self.dicoType.setItemText(1, _translate("filterDico", "Content", None))
        self.dicoMatch.setItemText(0, _translate("filterDico", "Any", None))
        self.dicoMatch.setItemText(1, _translate("filterDico", "All", None))
        self.dicoMatch.setItemText(2, _translate("filterDico", "None", None))

import gui_rc

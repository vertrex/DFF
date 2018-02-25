# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/filter_fields.ui'
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

class Ui_filterFields(object):
    def setupUi(self, filterFields):
        filterFields.setObjectName(_fromUtf8("filterFields"))
        filterFields.resize(640, 45)
        self.fieldCombo = QtGui.QComboBox(filterFields)
        self.fieldCombo.setGeometry(QtCore.QRect(9, 9, 124, 27))
        self.fieldCombo.setObjectName(_fromUtf8("fieldCombo"))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))
        self.fieldCombo.addItem(_fromUtf8(""))

        self.retranslateUi(filterFields)
        QtCore.QMetaObject.connectSlotsByName(filterFields)

    def retranslateUi(self, filterFields):
        filterFields.setWindowTitle(_translate("filterFields", "Form", None))
        self.fieldCombo.setItemText(0, _translate("filterFields", "Name", None))
        self.fieldCombo.setItemText(1, _translate("filterFields", "Contains", None))
        self.fieldCombo.setItemText(2, _translate("filterFields", "Size", None))
        self.fieldCombo.setItemText(3, _translate("filterFields", "Date", None))
        self.fieldCombo.setItemText(4, _translate("filterFields", "Type", None))
        self.fieldCombo.setItemText(5, _translate("filterFields", "Dictionnary", None))
        self.fieldCombo.setItemText(6, _translate("filterFields", "Is deleted", None))
        self.fieldCombo.setItemText(7, _translate("filterFields", "Is file", None))
        self.fieldCombo.setItemText(8, _translate("filterFields", "Attribute", None))
        self.fieldCombo.setItemText(9, _translate("filterFields", "Path", None))
        self.fieldCombo.setItemText(10, _translate("filterFields", "Extension", None))
        self.fieldCombo.setItemText(11, _translate("filterFields", "Tags", None))
        self.fieldCombo.setItemText(12, _translate("filterFields", "Module", None))
        self.fieldCombo.setItemText(13, _translate("filterFields", "Expression", None))


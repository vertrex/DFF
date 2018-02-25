# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/varianttreewidget.ui'
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

class Ui_VariantTreeWidget(object):
    def setupUi(self, VariantTreeWidget):
        VariantTreeWidget.setObjectName(_fromUtf8("VariantTreeWidget"))
        VariantTreeWidget.resize(256, 192)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(VariantTreeWidget.sizePolicy().hasHeightForWidth())
        VariantTreeWidget.setSizePolicy(sizePolicy)
        VariantTreeWidget.setAlternatingRowColors(True)
        self.useless = QtGui.QWidget(VariantTreeWidget)
        self.useless.setObjectName(_fromUtf8("useless"))
        self.useless1 = QtGui.QWidget(VariantTreeWidget)
        self.useless1.setGeometry(QtCore.QRect(0, 0, 100, 30))
        self.useless1.setObjectName(_fromUtf8("useless1"))

        self.retranslateUi(VariantTreeWidget)
        QtCore.QMetaObject.connectSlotsByName(VariantTreeWidget)

    def retranslateUi(self, VariantTreeWidget):
        VariantTreeWidget.headerItem().setText(0, _translate("VariantTreeWidget", "Attribute", None))
        VariantTreeWidget.headerItem().setText(1, _translate("VariantTreeWidget", "Value", None))


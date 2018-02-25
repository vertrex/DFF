# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/filter_widget.ui'
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

class Ui_filterWidget(object):
    def setupUi(self, filterWidget):
        filterWidget.setObjectName(_fromUtf8("filterWidget"))
        filterWidget.resize(757, 34)
        filterWidget.setStyleSheet(_fromUtf8(""))
        self.verticalLayout = QtGui.QVBoxLayout(filterWidget)
        self.verticalLayout.setMargin(0)
        self.verticalLayout.setSpacing(0)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.countlabel = QtGui.QLabel(filterWidget)
        self.countlabel.setObjectName(_fromUtf8("countlabel"))
        self.horizontalLayout.addWidget(self.countlabel)
        self.on = QtGui.QLabel(filterWidget)
        self.on.setObjectName(_fromUtf8("on"))
        self.horizontalLayout.addWidget(self.on)
        self.reslabel = QtGui.QLabel(filterWidget)
        self.reslabel.setObjectName(_fromUtf8("reslabel"))
        self.horizontalLayout.addWidget(self.reslabel)
        self.mode = QtGui.QComboBox(filterWidget)
        self.mode.setObjectName(_fromUtf8("mode"))
        self.mode.addItem(_fromUtf8(""))
        self.mode.addItem(_fromUtf8(""))
        self.mode.addItem(_fromUtf8(""))
        self.mode.addItem(_fromUtf8(""))
        self.mode.addItem(_fromUtf8(""))
        self.mode.addItem(_fromUtf8(""))
        self.horizontalLayout.addWidget(self.mode)
        self.filterCombo = QtGui.QComboBox(filterWidget)
        self.filterCombo.setEditable(True)
        self.filterCombo.setObjectName(_fromUtf8("filterCombo"))
        self.horizontalLayout.addWidget(self.filterCombo)
        self.lock = QtGui.QToolButton(filterWidget)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/encrypted")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.lock.setIcon(icon)
        self.lock.setCheckable(True)
        self.lock.setObjectName(_fromUtf8("lock"))
        self.horizontalLayout.addWidget(self.lock)
        self.stop = QtGui.QToolButton(filterWidget)
        self.stop.setEnabled(False)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8(":/mail_delete")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.stop.setIcon(icon1)
        self.stop.setObjectName(_fromUtf8("stop"))
        self.horizontalLayout.addWidget(self.stop)
        self.clear = QtGui.QToolButton(filterWidget)
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(_fromUtf8(":/previous.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.clear.setIcon(icon2)
        self.clear.setObjectName(_fromUtf8("clear"))
        self.horizontalLayout.addWidget(self.clear)
        self.horizontalLayout.setStretch(4, 100)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(filterWidget)
        QtCore.QMetaObject.connectSlotsByName(filterWidget)

    def retranslateUi(self, filterWidget):
        filterWidget.setWindowTitle(_translate("filterWidget", "Form", None))
        self.countlabel.setText(_translate("filterWidget", "0", None))
        self.on.setText(_translate("filterWidget", " / ", None))
        self.reslabel.setText(_translate("filterWidget", "0", None))
        self.mode.setItemText(0, _translate("filterWidget", "Wildcard", None))
        self.mode.setItemText(1, _translate("filterWidget", "Fuzzy", None))
        self.mode.setItemText(2, _translate("filterWidget", "Reg exp", None))
        self.mode.setItemText(3, _translate("filterWidget", "Fixed", None))
        self.mode.setItemText(4, _translate("filterWidget", "Custom query", None))
        self.mode.setItemText(5, _translate("filterWidget", "Tags", None))
        self.lock.setText(_translate("filterWidget", "...", None))
        self.stop.setToolTip(_translate("filterWidget", "Stop filter", None))
        self.stop.setText(_translate("filterWidget", "...", None))
        self.clear.setToolTip(_translate("filterWidget", "Clear filter", None))
        self.clear.setText(_translate("filterWidget", "Clear", None))

import gui_rc

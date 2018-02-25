# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/filter_mode.ui'
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

class Ui_filterMode(object):
    def setupUi(self, filterMode):
        filterMode.setObjectName(_fromUtf8("filterMode"))
        filterMode.resize(667, 29)
        filterMode.setStyleSheet(_fromUtf8(""))
        self.horizontalLayout_2 = QtGui.QHBoxLayout(filterMode)
        self.horizontalLayout_2.setMargin(0)
        self.horizontalLayout_2.setSpacing(0)
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setSpacing(0)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.label_2 = QtGui.QLabel(filterMode)
        self.label_2.setStyleSheet(_fromUtf8("QLabel {color : green; }"))
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.horizontalLayout.addWidget(self.label_2)
        self.count = QtGui.QLabel(filterMode)
        self.count.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.count.setObjectName(_fromUtf8("count"))
        self.horizontalLayout.addWidget(self.count)
        self.label = QtGui.QLabel(filterMode)
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayout.addWidget(self.label)
        self.closeFilterMode = QtGui.QPushButton(filterMode)
        self.closeFilterMode.setMaximumSize(QtCore.QSize(24, 24))
        self.closeFilterMode.setText(_fromUtf8(""))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/cancel.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.closeFilterMode.setIcon(icon)
        self.closeFilterMode.setIconSize(QtCore.QSize(16, 16))
        self.closeFilterMode.setFlat(True)
        self.closeFilterMode.setObjectName(_fromUtf8("closeFilterMode"))
        self.horizontalLayout.addWidget(self.closeFilterMode)
        self.horizontalLayout.setStretch(0, 50)
        self.horizontalLayout.setStretch(1, 60)
        self.horizontalLayout.setStretch(2, 20)
        self.horizontalLayout_2.addLayout(self.horizontalLayout)

        self.retranslateUi(filterMode)
        QtCore.QMetaObject.connectSlotsByName(filterMode)

    def retranslateUi(self, filterMode):
        filterMode.setWindowTitle(_translate("filterMode", "Form", None))
        self.label_2.setText(_translate("filterMode", "  Filter activated", None))
        self.count.setText(_translate("filterMode", "11", None))
        self.label.setText(_translate("filterMode", "  Found", None))

import gui_rc

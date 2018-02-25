# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/filter_bar.ui'
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

class Ui_filterBar(object):
    def setupUi(self, filterBar):
        filterBar.setObjectName(_fromUtf8("filterBar"))
        filterBar.resize(453, 30)
        self.horizontalLayout_2 = QtGui.QHBoxLayout(filterBar)
        self.horizontalLayout_2.setMargin(0)
        self.horizontalLayout_2.setSpacing(0)
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setSpacing(0)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.execFilter = QtGui.QPushButton(filterBar)
        self.execFilter.setMaximumSize(QtCore.QSize(16777215, 28))
        self.execFilter.setStyleSheet(_fromUtf8("\n"
"QPushButton {\n"
"    color: lightgreen;\n"
" }\n"
"QPushButton:checked {\n"
"    color: lightgreen;\n"
" }"))
        self.execFilter.setText(_fromUtf8(""))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/run.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.execFilter.setIcon(icon)
        self.execFilter.setIconSize(QtCore.QSize(18, 24))
        self.execFilter.setCheckable(False)
        self.execFilter.setObjectName(_fromUtf8("execFilter"))
        self.horizontalLayout.addWidget(self.execFilter)
        self.filterEdit = QtGui.QLineEdit(filterBar)
        self.filterEdit.setObjectName(_fromUtf8("filterEdit"))
        self.horizontalLayout.addWidget(self.filterEdit)
        self.showFilters = QtGui.QPushButton(filterBar)
        self.showFilters.setMaximumSize(QtCore.QSize(18, 28))
        self.showFilters.setText(_fromUtf8(""))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8(":/add.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.showFilters.setIcon(icon1)
        self.showFilters.setIconSize(QtCore.QSize(18, 24))
        self.showFilters.setFlat(True)
        self.showFilters.setObjectName(_fromUtf8("showFilters"))
        self.horizontalLayout.addWidget(self.showFilters)
        self.horizontalLayout.setStretch(1, 100)
        self.horizontalLayout_2.addLayout(self.horizontalLayout)

        self.retranslateUi(filterBar)
        QtCore.QMetaObject.connectSlotsByName(filterBar)

    def retranslateUi(self, filterBar):
        filterBar.setWindowTitle(_translate("filterBar", "Form", None))

import gui_rc

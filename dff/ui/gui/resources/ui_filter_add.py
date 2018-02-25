# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/filter_add.ui'
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

class Ui_filterAdd(object):
    def setupUi(self, filterAdd):
        filterAdd.setObjectName(_fromUtf8("filterAdd"))
        filterAdd.resize(640, 480)
        self.verticalLayout = QtGui.QVBoxLayout(filterAdd)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.filterIcon = QtGui.QLabel(filterAdd)
        self.filterIcon.setMaximumSize(QtCore.QSize(32, 32))
        self.filterIcon.setBaseSize(QtCore.QSize(32, 32))
        self.filterIcon.setText(_fromUtf8(""))
        self.filterIcon.setPixmap(QtGui.QPixmap(_fromUtf8(":/filter")))
        self.filterIcon.setScaledContents(True)
        self.filterIcon.setObjectName(_fromUtf8("filterIcon"))
        self.horizontalLayout.addWidget(self.filterIcon)
        self.headerLabel = QtGui.QLabel(filterAdd)
        self.headerLabel.setObjectName(_fromUtf8("headerLabel"))
        self.horizontalLayout.addWidget(self.headerLabel)
        self.horizontalLayout.setStretch(1, 50)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.filterLabel = QtGui.QLabel(filterAdd)
        self.filterLabel.setObjectName(_fromUtf8("filterLabel"))
        self.horizontalLayout_2.addWidget(self.filterLabel)
        self.filterName = QtGui.QLineEdit(filterAdd)
        self.filterName.setObjectName(_fromUtf8("filterName"))
        self.horizontalLayout_2.addWidget(self.filterName)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.requestLayout = QtGui.QVBoxLayout()
        self.requestLayout.setObjectName(_fromUtf8("requestLayout"))
        self.verticalLayout.addLayout(self.requestLayout)
        self.buttonBox = QtGui.QDialogButtonBox(filterAdd)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.verticalLayout.addWidget(self.buttonBox)
        self.verticalLayout.setStretch(2, 100)

        self.retranslateUi(filterAdd)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), filterAdd.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), filterAdd.reject)
        QtCore.QMetaObject.connectSlotsByName(filterAdd)

    def retranslateUi(self, filterAdd):
        filterAdd.setWindowTitle(_translate("filterAdd", "Add custom filter queries", None))
        self.headerLabel.setText(_translate("filterAdd", "Create your custom filter", None))
        self.filterLabel.setText(_translate("filterAdd", "Filter name", None))

import gui_rc

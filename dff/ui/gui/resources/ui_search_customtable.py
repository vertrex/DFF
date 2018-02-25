# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/search_customtable.ui'
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

class Ui_searchCustomTable(object):
    def setupUi(self, searchCustomTable):
        searchCustomTable.setObjectName(_fromUtf8("searchCustomTable"))
        searchCustomTable.resize(580, 390)
        self.verticalLayout = QtGui.QVBoxLayout(searchCustomTable)
        self.verticalLayout.setMargin(0)
        self.verticalLayout.setSpacing(0)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setContentsMargins(-1, -1, -1, 5)
        self.horizontalLayout_2.setSpacing(5)
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem)
        self.newButton = QtGui.QPushButton(searchCustomTable)
        self.newButton.setEnabled(True)
        self.newButton.setMinimumSize(QtCore.QSize(16, 16))
        self.newButton.setMaximumSize(QtCore.QSize(30, 32))
        self.newButton.setText(_fromUtf8(""))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/add.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.newButton.setIcon(icon)
        self.newButton.setIconSize(QtCore.QSize(16, 24))
        self.newButton.setObjectName(_fromUtf8("newButton"))
        self.horizontalLayout_2.addWidget(self.newButton)
        self.deleteButton = QtGui.QPushButton(searchCustomTable)
        self.deleteButton.setMaximumSize(QtCore.QSize(30, 32))
        self.deleteButton.setText(_fromUtf8(""))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8(":/remove.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.deleteButton.setIcon(icon1)
        self.deleteButton.setIconSize(QtCore.QSize(16, 24))
        self.deleteButton.setObjectName(_fromUtf8("deleteButton"))
        self.horizontalLayout_2.addWidget(self.deleteButton)
        self.editButton = QtGui.QPushButton(searchCustomTable)
        self.editButton.setMaximumSize(QtCore.QSize(30, 32))
        self.editButton.setText(_fromUtf8(""))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(_fromUtf8(":/configure.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.editButton.setIcon(icon2)
        self.editButton.setIconSize(QtCore.QSize(24, 24))
        self.editButton.setObjectName(_fromUtf8("editButton"))
        self.horizontalLayout_2.addWidget(self.editButton)
        self.saveButton = QtGui.QToolButton(searchCustomTable)
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(_fromUtf8(":/filesave.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.saveButton.setIcon(icon3)
        self.saveButton.setObjectName(_fromUtf8("saveButton"))
        self.horizontalLayout_2.addWidget(self.saveButton)
        self.loadButton = QtGui.QToolButton(searchCustomTable)
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(_fromUtf8(":/folder_documents_128.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.loadButton.setIcon(icon4)
        self.loadButton.setObjectName(_fromUtf8("loadButton"))
        self.horizontalLayout_2.addWidget(self.loadButton)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.table = QtGui.QTableWidget(searchCustomTable)
        self.table.setColumnCount(2)
        self.table.setObjectName(_fromUtf8("table"))
        self.table.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap(_fromUtf8(":/filter")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        item.setIcon(icon5)
        self.table.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.table.setHorizontalHeaderItem(1, item)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.verticalLayout.addWidget(self.table)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setContentsMargins(-1, 5, -1, -1)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(searchCustomTable)
        QtCore.QMetaObject.connectSlotsByName(searchCustomTable)

    def retranslateUi(self, searchCustomTable):
        searchCustomTable.setWindowTitle(_translate("searchCustomTable", "Form", None))
        self.saveButton.setText(_translate("searchCustomTable", "...", None))
        self.loadButton.setText(_translate("searchCustomTable", "...", None))
        item = self.table.horizontalHeaderItem(0)
        item.setText(_translate("searchCustomTable", "Query name", None))
        item = self.table.horizontalHeaderItem(1)
        item.setText(_translate("searchCustomTable", "Enabled", None))

import gui_rc

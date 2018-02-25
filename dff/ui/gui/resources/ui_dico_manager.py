# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/dico_manager.ui'
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

class Ui_dicoManager(object):
    def setupUi(self, dicoManager):
        dicoManager.setObjectName(_fromUtf8("dicoManager"))
        dicoManager.resize(614, 369)
        self.verticalLayout = QtGui.QVBoxLayout(dicoManager)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.label_2 = QtGui.QLabel(dicoManager)
        self.label_2.setText(_fromUtf8(""))
        self.label_2.setPixmap(QtGui.QPixmap(_fromUtf8(":/dict.png")))
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.horizontalLayout.addWidget(self.label_2)
        self.label = QtGui.QLabel(dicoManager)
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayout.addWidget(self.label)
        self.horizontalLayout.setStretch(1, 100)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setContentsMargins(-1, -1, -1, 0)
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.addDico = QtGui.QToolButton(dicoManager)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/add_dico")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.addDico.setIcon(icon)
        self.addDico.setToolButtonStyle(QtCore.Qt.ToolButtonTextBesideIcon)
        self.addDico.setObjectName(_fromUtf8("addDico"))
        self.horizontalLayout_2.addWidget(self.addDico)
        self.rmDico = QtGui.QToolButton(dicoManager)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8(":/del_dump.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.rmDico.setIcon(icon1)
        self.rmDico.setToolButtonStyle(QtCore.Qt.ToolButtonTextBesideIcon)
        self.rmDico.setObjectName(_fromUtf8("rmDico"))
        self.horizontalLayout_2.addWidget(self.rmDico)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.dicos = QtGui.QTableWidget(dicoManager)
        self.dicos.setSelectionMode(QtGui.QAbstractItemView.SingleSelection)
        self.dicos.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.dicos.setObjectName(_fromUtf8("dicos"))
        self.dicos.setColumnCount(2)
        self.dicos.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        self.dicos.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.dicos.setHorizontalHeaderItem(1, item)
        self.dicos.horizontalHeader().setStretchLastSection(True)
        self.dicos.verticalHeader().setVisible(False)
        self.horizontalLayout_3.addWidget(self.dicos)
        self.verticalLayout.addLayout(self.horizontalLayout_3)

        self.retranslateUi(dicoManager)
        QtCore.QMetaObject.connectSlotsByName(dicoManager)

    def retranslateUi(self, dicoManager):
        dicoManager.setWindowTitle(_translate("dicoManager", "Form", None))
        self.label.setText(_translate("dicoManager", "Dictionnary manager", None))
        self.addDico.setText(_translate("dicoManager", "Add dictionnary", None))
        self.rmDico.setText(_translate("dicoManager", "Remove dictionnary", None))
        item = self.dicos.horizontalHeaderItem(0)
        item.setText(_translate("dicoManager", "Location", None))
        item = self.dicos.horizontalHeaderItem(1)
        item.setText(_translate("dicoManager", "Dictionnary\'s name", None))

import gui_rc

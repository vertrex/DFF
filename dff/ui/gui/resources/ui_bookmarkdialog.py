# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/bookmarkdialog.ui'
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

class Ui_AddBookmark(object):
    def setupUi(self, AddBookmark):
        AddBookmark.setObjectName(_fromUtf8("AddBookmark"))
        self.verticalLayout_2 = QtGui.QVBoxLayout(AddBookmark)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.label = QtGui.QLabel(AddBookmark)
        self.label.setText(_fromUtf8(""))
        self.label.setPixmap(QtGui.QPixmap(_fromUtf8(":/bookmark.png")))
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayout.addWidget(self.label)
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.label_2 = QtGui.QLabel(AddBookmark)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.verticalLayout.addWidget(self.label_2)
        spacerItem = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem)
        self.horizontalLayout.addLayout(self.verticalLayout)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.newBox = QtGui.QGroupBox(AddBookmark)
        self.newBox.setFlat(False)
        self.newBox.setCheckable(True)
        self.newBox.setObjectName(_fromUtf8("newBox"))
        self.horizontalLayout_2 = QtGui.QHBoxLayout(self.newBox)
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.label_3 = QtGui.QLabel(self.newBox)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.horizontalLayout_2.addWidget(self.label_3)
        self.catname = QtGui.QLineEdit(self.newBox)
        self.catname.setObjectName(_fromUtf8("catname"))
        self.horizontalLayout_2.addWidget(self.catname)
        self.verticalLayout_2.addWidget(self.newBox)
        self.existBox = QtGui.QGroupBox(AddBookmark)
        self.existBox.setCheckable(True)
        self.existBox.setChecked(False)
        self.existBox.setObjectName(_fromUtf8("existBox"))
        self.horizontalLayout_3 = QtGui.QHBoxLayout(self.existBox)
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.label_4 = QtGui.QLabel(self.existBox)
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.horizontalLayout_3.addWidget(self.label_4)
        self.catcombo = QtGui.QComboBox(self.existBox)
        self.catcombo.setObjectName(_fromUtf8("catcombo"))
        self.horizontalLayout_3.addWidget(self.catcombo)
        self.verticalLayout_2.addWidget(self.existBox)
        self.buttonBox = QtGui.QDialogButtonBox(AddBookmark)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.verticalLayout_2.addWidget(self.buttonBox)

        self.retranslateUi(AddBookmark)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), AddBookmark.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), AddBookmark.reject)
        QtCore.QMetaObject.connectSlotsByName(AddBookmark)

    def retranslateUi(self, AddBookmark):
        AddBookmark.setWindowTitle(_translate("AddBookmark", "Add bookmark", None))
        self.label_2.setText(_translate("AddBookmark", "Add a bookmark from the Virtual File System", None))
        self.newBox.setTitle(_translate("AddBookmark", "Create a new category", None))
        self.label_3.setText(_translate("AddBookmark", "Category name:", None))
        self.existBox.setTitle(_translate("AddBookmark", "Add to existing category", None))
        self.label_4.setText(_translate("AddBookmark", "Category name:", None))

import gui_rc

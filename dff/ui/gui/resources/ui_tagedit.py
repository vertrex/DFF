# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/tagedit.ui'
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

class Ui_edittag(object):
    def setupUi(self, edittag):
        edittag.setObjectName(_fromUtf8("edittag"))
        edittag.resize(395, 116)
        self.verticalLayout = QtGui.QVBoxLayout(edittag)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.nameLabel = QtGui.QLabel(edittag)
        self.nameLabel.setObjectName(_fromUtf8("nameLabel"))
        self.horizontalLayout.addWidget(self.nameLabel)
        self.tagEdit = QtGui.QLineEdit(edittag)
        self.tagEdit.setObjectName(_fromUtf8("tagEdit"))
        self.horizontalLayout.addWidget(self.tagEdit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.setColorButton = QtGui.QPushButton(edittag)
        self.setColorButton.setObjectName(_fromUtf8("setColorButton"))
        self.verticalLayout.addWidget(self.setColorButton)
        self.buttonBox = QtGui.QDialogButtonBox(edittag)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.verticalLayout.addWidget(self.buttonBox)
        self.nameLabel.setBuddy(self.tagEdit)

        self.retranslateUi(edittag)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), edittag.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), edittag.reject)
        QtCore.QMetaObject.connectSlotsByName(edittag)

    def retranslateUi(self, edittag):
        edittag.setWindowTitle(_translate("edittag", "Edit tag", None))
        self.nameLabel.setText(_translate("edittag", "Name :", None))
        self.tagEdit.setText(_translate("edittag", "Default", None))
        self.setColorButton.setText(_translate("edittag", "set color", None))


# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/extractdialog.ui'
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

class Ui_ExtractDialog(object):
    def setupUi(self, ExtractDialog):
        ExtractDialog.setObjectName(_fromUtf8("ExtractDialog"))
        ExtractDialog.resize(467, 191)
        self.verticalLayout = QtGui.QVBoxLayout(ExtractDialog)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.icon = QtGui.QLabel(ExtractDialog)
        self.icon.setText(_fromUtf8(""))
        self.icon.setPixmap(QtGui.QPixmap(_fromUtf8(":/extract.png")))
        self.icon.setObjectName(_fromUtf8("icon"))
        self.horizontalLayout.addWidget(self.icon)
        self.recurseCheck = QtGui.QCheckBox(ExtractDialog)
        self.recurseCheck.setObjectName(_fromUtf8("recurseCheck"))
        self.horizontalLayout.addWidget(self.recurseCheck)
        self.preserveTree = QtGui.QCheckBox(ExtractDialog)
        self.preserveTree.setObjectName(_fromUtf8("preserveTree"))
        self.horizontalLayout.addWidget(self.preserveTree)
        self.overwriteExisting = QtGui.QCheckBox(ExtractDialog)
        self.overwriteExisting.setObjectName(_fromUtf8("overwriteExisting"))
        self.horizontalLayout.addWidget(self.overwriteExisting)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.label = QtGui.QLabel(ExtractDialog)
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayout_2.addWidget(self.label)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.syspathLine = QtGui.QLineEdit(ExtractDialog)
        self.syspathLine.setObjectName(_fromUtf8("syspathLine"))
        self.horizontalLayout_3.addWidget(self.syspathLine)
        self.syspathBrowse = QtGui.QPushButton(ExtractDialog)
        self.syspathBrowse.setObjectName(_fromUtf8("syspathBrowse"))
        self.horizontalLayout_3.addWidget(self.syspathBrowse)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.horizontalLayout_5 = QtGui.QHBoxLayout()
        self.horizontalLayout_5.setObjectName(_fromUtf8("horizontalLayout_5"))
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_5.addItem(spacerItem)
        self.buttonBox = QtGui.QDialogButtonBox(ExtractDialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.horizontalLayout_5.addWidget(self.buttonBox)
        self.verticalLayout.addLayout(self.horizontalLayout_5)

        self.retranslateUi(ExtractDialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), ExtractDialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), ExtractDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(ExtractDialog)

    def retranslateUi(self, ExtractDialog):
        ExtractDialog.setWindowTitle(_translate("ExtractDialog", "Extract", None))
        self.recurseCheck.setText(_translate("ExtractDialog", "Recursive mode", None))
        self.preserveTree.setText(_translate("ExtractDialog", "Preserve tree", None))
        self.overwriteExisting.setText(_translate("ExtractDialog", "Overwrite existing", None))
        self.label.setText(_translate("ExtractDialog", "Destination folder:", None))
        self.syspathBrowse.setText(_translate("ExtractDialog", "Browse", None))

import gui_rc

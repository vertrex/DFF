# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/evidencedialog.ui'
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

class Ui_evidenceDialog(object):
    def setupUi(self, evidenceDialog):
        evidenceDialog.setObjectName(_fromUtf8("evidenceDialog"))
        evidenceDialog.setWindowModality(QtCore.Qt.NonModal)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(15)
        sizePolicy.setHeightForWidth(evidenceDialog.sizePolicy().hasHeightForWidth())
        evidenceDialog.setSizePolicy(sizePolicy)
        evidenceDialog.setMinimumSize(QtCore.QSize(400, 0))
        evidenceDialog.setMaximumSize(QtCore.QSize(16777215, 400))
        evidenceDialog.setSizeGripEnabled(False)
        self.verticalLayout = QtGui.QVBoxLayout(evidenceDialog)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.label_3 = QtGui.QLabel(evidenceDialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_3.sizePolicy().hasHeightForWidth())
        self.label_3.setSizePolicy(sizePolicy)
        self.label_3.setText(_fromUtf8(""))
        self.label_3.setPixmap(QtGui.QPixmap(_fromUtf8(":/fileopen.png")))
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.horizontalLayout.addWidget(self.label_3)
        self.label = QtGui.QLabel(evidenceDialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(7)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy)
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayout.addWidget(self.label)
        self.horizontalLayout.setStretch(0, 1)
        self.horizontalLayout.setStretch(1, 10)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.rawcheck = QtGui.QCheckBox(evidenceDialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.rawcheck.sizePolicy().hasHeightForWidth())
        self.rawcheck.setSizePolicy(sizePolicy)
        self.rawcheck.setAutoExclusive(True)
        self.rawcheck.setObjectName(_fromUtf8("rawcheck"))
        self.horizontalLayout_2.addWidget(self.rawcheck)
        self.ewfcheck = QtGui.QCheckBox(evidenceDialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(7)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.ewfcheck.sizePolicy().hasHeightForWidth())
        self.ewfcheck.setSizePolicy(sizePolicy)
        self.ewfcheck.setAutoExclusive(True)
        self.ewfcheck.setObjectName(_fromUtf8("ewfcheck"))
        self.horizontalLayout_2.addWidget(self.ewfcheck)
        self.affcheck = QtGui.QCheckBox(evidenceDialog)
        self.affcheck.setAutoExclusive(True)
        self.affcheck.setObjectName(_fromUtf8("affcheck"))
        self.horizontalLayout_2.addWidget(self.affcheck)
        self.horizontalLayout_2.setStretch(0, 1)
        self.horizontalLayout_2.setStretch(1, 1)
        self.horizontalLayout_2.setStretch(2, 10)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.pathlayout = QtGui.QVBoxLayout()
        self.pathlayout.setObjectName(_fromUtf8("pathlayout"))
        self.verticalLayout.addLayout(self.pathlayout)
        self.buttonBox = QtGui.QDialogButtonBox(evidenceDialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.verticalLayout.addWidget(self.buttonBox)
        self.verticalLayout.setStretch(0, 1)
        self.verticalLayout.setStretch(1, 1)
        self.verticalLayout.setStretch(2, 50)
        self.verticalLayout.setStretch(3, 1)
        self.actionAdd_evidence_directory = QtGui.QAction(evidenceDialog)
        self.actionAdd_evidence_directory.setObjectName(_fromUtf8("actionAdd_evidence_directory"))
        self.actionAdd_evidence_files = QtGui.QAction(evidenceDialog)
        self.actionAdd_evidence_files.setObjectName(_fromUtf8("actionAdd_evidence_files"))

        self.retranslateUi(evidenceDialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), evidenceDialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), evidenceDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(evidenceDialog)

    def retranslateUi(self, evidenceDialog):
        evidenceDialog.setWindowTitle(_translate("evidenceDialog", "Select evidence type", None))
        self.label.setText(_translate("evidenceDialog", "Open local files or folders", None))
        self.rawcheck.setText(_translate("evidenceDialog", "RAW format", None))
        self.ewfcheck.setText(_translate("evidenceDialog", "EWF format", None))
        self.affcheck.setText(_translate("evidenceDialog", "AFF Format", None))
        self.actionAdd_evidence_directory.setText(_translate("evidenceDialog", "Add evidence directory", None))
        self.actionAdd_evidence_files.setText(_translate("evidenceDialog", "Add evidence files", None))

import gui_rc

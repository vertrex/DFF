# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/applymodule.ui'
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

class Ui_applyModule(object):
    def setupUi(self, applyModule):
        applyModule.setObjectName(_fromUtf8("applyModule"))
        applyModule.resize(519, 398)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(applyModule.sizePolicy().hasHeightForWidth())
        applyModule.setSizePolicy(sizePolicy)
        self.verticalLayout = QtGui.QVBoxLayout(applyModule)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.infoContainer = QtGui.QGroupBox(applyModule)
        self.infoContainer.setObjectName(_fromUtf8("infoContainer"))
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.infoContainer)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.gridLayout = QtGui.QGridLayout()
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.modulepix = QtGui.QLabel(self.infoContainer)
        self.modulepix.setEnabled(True)
        self.modulepix.setMaximumSize(QtCore.QSize(64, 64))
        self.modulepix.setText(_fromUtf8(""))
        self.modulepix.setPixmap(QtGui.QPixmap(_fromUtf8(":/module2.png")))
        self.modulepix.setObjectName(_fromUtf8("modulepix"))
        self.gridLayout.addWidget(self.modulepix, 0, 0, 1, 1)
        self.textEdit = QtGui.QTextEdit(self.infoContainer)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(self.textEdit.sizePolicy().hasHeightForWidth())
        self.textEdit.setSizePolicy(sizePolicy)
        self.textEdit.setMinimumSize(QtCore.QSize(0, 64))
        self.textEdit.setMaximumSize(QtCore.QSize(16777215, 96))
        self.textEdit.setReadOnly(True)
        self.textEdit.setHtml(_fromUtf8("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Sans\'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
"<table border=\"0\" style=\"-qt-table-type: root; margin-top:4px; margin-bottom:4px; margin-left:4px; margin-right:4px;\">\n"
"<tr>\n"
"<td style=\"border: none;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans Serif\'; font-size:9pt;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans Serif\'; font-size:9pt;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans Serif\'; font-size:9pt;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans Serif\'; font-size:9pt;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans Serif\'; font-size:9pt;\"></p></td></tr></table></body></html>"))
        self.textEdit.setObjectName(_fromUtf8("textEdit"))
        self.gridLayout.addWidget(self.textEdit, 0, 1, 1, 1)
        self.label = QtGui.QLabel(self.infoContainer)
        self.label.setObjectName(_fromUtf8("label"))
        self.gridLayout.addWidget(self.label, 1, 0, 1, 1)
        self.nameModuleField = QtGui.QLabel(self.infoContainer)
        self.nameModuleField.setText(_fromUtf8("nameModule"))
        self.nameModuleField.setObjectName(_fromUtf8("nameModuleField"))
        self.gridLayout.addWidget(self.nameModuleField, 1, 1, 1, 1)
        self.label_2 = QtGui.QLabel(self.infoContainer)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.gridLayout.addWidget(self.label_2, 2, 0, 1, 1)
        self.typeModuleField = QtGui.QLabel(self.infoContainer)
        self.typeModuleField.setText(_fromUtf8("typeModule"))
        self.typeModuleField.setObjectName(_fromUtf8("typeModuleField"))
        self.gridLayout.addWidget(self.typeModuleField, 2, 1, 1, 1)
        self.verticalLayout_2.addLayout(self.gridLayout)
        self.verticalLayout.addWidget(self.infoContainer)
        self.argumentsContainer = QtGui.QGroupBox(applyModule)
        self.argumentsContainer.setObjectName(_fromUtf8("argumentsContainer"))
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.argumentsContainer)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.argsLayout = QtGui.QSplitter(self.argumentsContainer)
        self.argsLayout.setOrientation(QtCore.Qt.Horizontal)
        self.argsLayout.setObjectName(_fromUtf8("argsLayout"))
        self.listargs = QtGui.QListWidget(self.argsLayout)
        self.listargs.setObjectName(_fromUtf8("listargs"))
        self.stackedargs = QtGui.QStackedWidget(self.argsLayout)
        self.stackedargs.setObjectName(_fromUtf8("stackedargs"))
        self.verticalLayout_3.addWidget(self.argsLayout)
        self.labActivate = QtGui.QLabel(self.argumentsContainer)
        self.labActivate.setObjectName(_fromUtf8("labActivate"))
        self.verticalLayout_3.addWidget(self.labActivate)
        self.labType = QtGui.QLabel(self.argumentsContainer)
        self.labType.setObjectName(_fromUtf8("labType"))
        self.verticalLayout_3.addWidget(self.labType)
        self.labDescription = QtGui.QLabel(self.argumentsContainer)
        self.labDescription.setObjectName(_fromUtf8("labDescription"))
        self.verticalLayout_3.addWidget(self.labDescription)
        self.verticalLayout.addWidget(self.argumentsContainer)
        self.buttonBox = QtGui.QDialogButtonBox(applyModule)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.verticalLayout.addWidget(self.buttonBox)

        self.retranslateUi(applyModule)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), applyModule.reject)
        QtCore.QMetaObject.connectSlotsByName(applyModule)

    def retranslateUi(self, applyModule):
        applyModule.setWindowTitle(_translate("applyModule", "Apply module", None))
        self.infoContainer.setTitle(_translate("applyModule", "Information", None))
        self.label.setText(_translate("applyModule", "Module", None))
        self.label_2.setText(_translate("applyModule", "Type", None))
        self.argumentsContainer.setTitle(_translate("applyModule", "Arguments", None))
        self.labActivate.setText(_translate("applyModule", "Activate", None))
        self.labType.setText(_translate("applyModule", "Type", None))
        self.labDescription.setText(_translate("applyModule", "Description", None))

import gui_rc

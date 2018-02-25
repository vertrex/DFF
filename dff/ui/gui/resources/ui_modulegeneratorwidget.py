# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/modulegeneratorwidget.ui'
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

class Ui_moduleGeneratorWidget(object):
    def setupUi(self, moduleGeneratorWidget):
        moduleGeneratorWidget.setObjectName(_fromUtf8("moduleGeneratorWidget"))
        moduleGeneratorWidget.resize(500, 296)
        self.verticalLayout_3 = QtGui.QVBoxLayout(moduleGeneratorWidget)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.infoContainer = QtGui.QGroupBox(moduleGeneratorWidget)
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
"</style></head><body style=\" font-family:\'Ubuntu\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
"<table border=\"0\" style=\"-qt-table-type: root; margin-top:4px; margin-bottom:4px; margin-left:4px; margin-right:4px;\">\n"
"<tr>\n"
"<td style=\"border: none;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans\'; font-size:10pt;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans\'; font-size:10pt;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans\'; font-size:10pt;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans Serif\'; font-size:9pt;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans Serif\'; font-size:9pt;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans Serif\'; font-size:9pt;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans Serif\'; font-size:9pt;\"></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Sans Serif\'; font-size:9pt;\"></p></td></tr></table></body></html>"))
        self.textEdit.setObjectName(_fromUtf8("textEdit"))
        self.gridLayout.addWidget(self.textEdit, 0, 1, 1, 1)
        self.verticalLayout_2.addLayout(self.gridLayout)
        self.verticalLayout_3.addWidget(self.infoContainer)
        self.argumentsContainer = QtGui.QGroupBox(moduleGeneratorWidget)
        self.argumentsContainer.setObjectName(_fromUtf8("argumentsContainer"))
        self.verticalLayout = QtGui.QVBoxLayout(self.argumentsContainer)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.argsLayout = QtGui.QSplitter(self.argumentsContainer)
        self.argsLayout.setOrientation(QtCore.Qt.Horizontal)
        self.argsLayout.setObjectName(_fromUtf8("argsLayout"))
        self.listargs = QtGui.QListWidget(self.argsLayout)
        self.listargs.setObjectName(_fromUtf8("listargs"))
        self.stackedargs = QtGui.QStackedWidget(self.argsLayout)
        self.stackedargs.setObjectName(_fromUtf8("stackedargs"))
        self.verticalLayout.addWidget(self.argsLayout)
        self.labActivate = QtGui.QLabel(self.argumentsContainer)
        self.labActivate.setObjectName(_fromUtf8("labActivate"))
        self.verticalLayout.addWidget(self.labActivate)
        self.labDescription = QtGui.QLabel(self.argumentsContainer)
        self.labDescription.setObjectName(_fromUtf8("labDescription"))
        self.verticalLayout.addWidget(self.labDescription)
        spacerItem = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem)
        self.verticalLayout_3.addWidget(self.argumentsContainer)

        self.retranslateUi(moduleGeneratorWidget)
        QtCore.QMetaObject.connectSlotsByName(moduleGeneratorWidget)

    def retranslateUi(self, moduleGeneratorWidget):
        moduleGeneratorWidget.setWindowTitle(_translate("moduleGeneratorWidget", "Module", None))
        self.infoContainer.setTitle(_translate("moduleGeneratorWidget", "Information", None))
        self.argumentsContainer.setTitle(_translate("moduleGeneratorWidget", "Arguments", None))
        self.labActivate.setText(_translate("moduleGeneratorWidget", "Activate", None))
        self.labDescription.setText(_translate("moduleGeneratorWidget", "Description", None))

import gui_rc

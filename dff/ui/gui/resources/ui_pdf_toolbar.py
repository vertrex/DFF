# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/pdf_toolbar.ui'
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

class Ui_pdfToolbar(object):
    def setupUi(self, pdfToolbar):
        pdfToolbar.setObjectName(_fromUtf8("pdfToolbar"))
        pdfToolbar.resize(714, 256)
        self.verticalLayout_2 = QtGui.QVBoxLayout(pdfToolbar)
        self.verticalLayout_2.setMargin(0)
        self.verticalLayout_2.setSpacing(0)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.nextButton = QtGui.QPushButton(pdfToolbar)
        self.nextButton.setText(_fromUtf8(""))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/down.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.nextButton.setIcon(icon)
        self.nextButton.setObjectName(_fromUtf8("nextButton"))
        self.horizontalLayout.addWidget(self.nextButton)
        self.previousButton = QtGui.QPushButton(pdfToolbar)
        self.previousButton.setText(_fromUtf8(""))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8(":/top.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.previousButton.setIcon(icon1)
        self.previousButton.setAutoDefault(False)
        self.previousButton.setDefault(False)
        self.previousButton.setFlat(False)
        self.previousButton.setObjectName(_fromUtf8("previousButton"))
        self.horizontalLayout.addWidget(self.previousButton)
        self.label = QtGui.QLabel(pdfToolbar)
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayout.addWidget(self.label)
        self.selectPage = QtGui.QSpinBox(pdfToolbar)
        self.selectPage.setObjectName(_fromUtf8("selectPage"))
        self.horizontalLayout.addWidget(self.selectPage)
        self.label_4 = QtGui.QLabel(pdfToolbar)
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.horizontalLayout.addWidget(self.label_4)
        self.totalPages = QtGui.QLabel(pdfToolbar)
        self.totalPages.setText(_fromUtf8(""))
        self.totalPages.setObjectName(_fromUtf8("totalPages"))
        self.horizontalLayout.addWidget(self.totalPages)
        self.label_3 = QtGui.QLabel(pdfToolbar)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.horizontalLayout.addWidget(self.label_3)
        self.scaleBox = QtGui.QComboBox(pdfToolbar)
        self.scaleBox.setObjectName(_fromUtf8("scaleBox"))
        self.scaleBox.addItem(_fromUtf8(""))
        self.scaleBox.addItem(_fromUtf8(""))
        self.scaleBox.addItem(_fromUtf8(""))
        self.scaleBox.addItem(_fromUtf8(""))
        self.horizontalLayout.addWidget(self.scaleBox)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.stack = QtGui.QStackedWidget(pdfToolbar)
        self.stack.setObjectName(_fromUtf8("stack"))
        self.render = QtGui.QWidget()
        self.render.setObjectName(_fromUtf8("render"))
        self.horizontalLayout_5 = QtGui.QHBoxLayout(self.render)
        self.horizontalLayout_5.setMargin(0)
        self.horizontalLayout_5.setSpacing(0)
        self.horizontalLayout_5.setObjectName(_fromUtf8("horizontalLayout_5"))
        self.tabWidget = QtGui.QTabWidget(self.render)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.tab_2 = QtGui.QWidget()
        self.tab_2.setObjectName(_fromUtf8("tab_2"))
        self.horizontalLayout_3 = QtGui.QHBoxLayout(self.tab_2)
        self.horizontalLayout_3.setMargin(0)
        self.horizontalLayout_3.setSpacing(0)
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.renderSplitter = QtGui.QSplitter(self.tab_2)
        self.renderSplitter.setOrientation(QtCore.Qt.Horizontal)
        self.renderSplitter.setObjectName(_fromUtf8("renderSplitter"))
        self.verticalLayoutWidget = QtGui.QWidget(self.renderSplitter)
        self.verticalLayoutWidget.setObjectName(_fromUtf8("verticalLayoutWidget"))
        self.pdfscene = QtGui.QVBoxLayout(self.verticalLayoutWidget)
        self.pdfscene.setMargin(0)
        self.pdfscene.setObjectName(_fromUtf8("pdfscene"))
        self.annotationsEdit = QtGui.QPlainTextEdit(self.renderSplitter)
        self.annotationsEdit.setObjectName(_fromUtf8("annotationsEdit"))
        self.horizontalLayout_3.addWidget(self.renderSplitter)
        self.tabWidget.addTab(self.tab_2, _fromUtf8(""))
        self.tab = QtGui.QWidget()
        self.tab.setObjectName(_fromUtf8("tab"))
        self.horizontalLayout_2 = QtGui.QHBoxLayout(self.tab)
        self.horizontalLayout_2.setContentsMargins(0, 5, 0, 0)
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.scriptsTab = QtGui.QTabWidget(self.tab)
        self.scriptsTab.setObjectName(_fromUtf8("scriptsTab"))
        self.horizontalLayout_2.addWidget(self.scriptsTab)
        self.tabWidget.addTab(self.tab, _fromUtf8(""))
        self.tab_3 = QtGui.QWidget()
        self.tab_3.setObjectName(_fromUtf8("tab_3"))
        self.horizontalLayout_4 = QtGui.QHBoxLayout(self.tab_3)
        self.horizontalLayout_4.setMargin(0)
        self.horizontalLayout_4.setSpacing(0)
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        self.metadataEdit = QtGui.QPlainTextEdit(self.tab_3)
        self.metadataEdit.setObjectName(_fromUtf8("metadataEdit"))
        self.horizontalLayout_4.addWidget(self.metadataEdit)
        self.tabWidget.addTab(self.tab_3, _fromUtf8(""))
        self.horizontalLayout_5.addWidget(self.tabWidget)
        self.stack.addWidget(self.render)
        self.page_2 = QtGui.QWidget()
        self.page_2.setObjectName(_fromUtf8("page_2"))
        self.horizontalLayout_8 = QtGui.QHBoxLayout(self.page_2)
        self.horizontalLayout_8.setMargin(0)
        self.horizontalLayout_8.setObjectName(_fromUtf8("horizontalLayout_8"))
        spacerItem1 = QtGui.QSpacerItem(221, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_8.addItem(spacerItem1)
        self.widget = QtGui.QWidget(self.page_2)
        self.widget.setObjectName(_fromUtf8("widget"))
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.widget)
        self.verticalLayout_3.setMargin(0)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        spacerItem2 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout_3.addItem(spacerItem2)
        self.label_8 = QtGui.QLabel(self.widget)
        self.label_8.setObjectName(_fromUtf8("label_8"))
        self.verticalLayout_3.addWidget(self.label_8)
        self.label_9 = QtGui.QLabel(self.widget)
        self.label_9.setObjectName(_fromUtf8("label_9"))
        self.verticalLayout_3.addWidget(self.label_9)
        self.owneredit = QtGui.QLineEdit(self.widget)
        self.owneredit.setObjectName(_fromUtf8("owneredit"))
        self.verticalLayout_3.addWidget(self.owneredit)
        self.label_10 = QtGui.QLabel(self.widget)
        self.label_10.setObjectName(_fromUtf8("label_10"))
        self.verticalLayout_3.addWidget(self.label_10)
        self.useredit = QtGui.QLineEdit(self.widget)
        self.useredit.setObjectName(_fromUtf8("useredit"))
        self.verticalLayout_3.addWidget(self.useredit)
        self.horizontalLayout_7 = QtGui.QHBoxLayout()
        self.horizontalLayout_7.setObjectName(_fromUtf8("horizontalLayout_7"))
        spacerItem3 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_7.addItem(spacerItem3)
        self.unlockButton = QtGui.QPushButton(self.widget)
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(_fromUtf8(":/password.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.unlockButton.setIcon(icon2)
        self.unlockButton.setObjectName(_fromUtf8("unlockButton"))
        self.horizontalLayout_7.addWidget(self.unlockButton)
        self.verticalLayout_3.addLayout(self.horizontalLayout_7)
        spacerItem4 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout_3.addItem(spacerItem4)
        self.horizontalLayout_8.addWidget(self.widget)
        spacerItem5 = QtGui.QSpacerItem(220, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_8.addItem(spacerItem5)
        self.stack.addWidget(self.page_2)
        self.verticalLayout_2.addWidget(self.stack)

        self.retranslateUi(pdfToolbar)
        self.stack.setCurrentIndex(0)
        self.tabWidget.setCurrentIndex(0)
        self.scriptsTab.setCurrentIndex(-1)
        QtCore.QMetaObject.connectSlotsByName(pdfToolbar)

    def retranslateUi(self, pdfToolbar):
        pdfToolbar.setWindowTitle(_translate("pdfToolbar", "Form", None))
        self.label.setText(_translate("pdfToolbar", "Page", None))
        self.label_4.setText(_translate("pdfToolbar", " / ", None))
        self.label_3.setText(_translate("pdfToolbar", "    Scale resolution", None))
        self.scaleBox.setItemText(0, _translate("pdfToolbar", "72", None))
        self.scaleBox.setItemText(1, _translate("pdfToolbar", "96", None))
        self.scaleBox.setItemText(2, _translate("pdfToolbar", "120", None))
        self.scaleBox.setItemText(3, _translate("pdfToolbar", "300", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("pdfToolbar", "Render", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("pdfToolbar", "Scripts", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("pdfToolbar", "Metadata", None))
        self.label_8.setText(_translate("pdfToolbar", "Document is password protected", None))
        self.label_9.setText(_translate("pdfToolbar", "Owner password", None))
        self.label_10.setText(_translate("pdfToolbar", "User password (optional)", None))
        self.unlockButton.setText(_translate("pdfToolbar", "Unlock", None))

import gui_rc
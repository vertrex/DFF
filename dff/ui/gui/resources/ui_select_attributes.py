# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/select_attributes.ui'
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

class Ui_SelectAttributesWiz(object):
    def setupUi(self, SelectAttributesWiz):
        SelectAttributesWiz.setObjectName(_fromUtf8("SelectAttributesWiz"))
        SelectAttributesWiz.resize(505, 361)
        self.wizardPage = QtGui.QWizardPage()
        self.wizardPage.setObjectName(_fromUtf8("wizardPage"))
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.wizardPage)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.label = QtGui.QLabel(self.wizardPage)
        self.label.setText(_fromUtf8(""))
        self.label.setPixmap(QtGui.QPixmap(_fromUtf8(":/menuedit")))
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayout.addWidget(self.label)
        self.label_2 = QtGui.QLabel(self.wizardPage)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.horizontalLayout.addWidget(self.label_2)
        self.horizontalLayout.setStretch(1, 100)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.groupBox = QtGui.QGroupBox(self.wizardPage)
        self.groupBox.setObjectName(_fromUtf8("groupBox"))
        self.verticalLayout_5 = QtGui.QVBoxLayout(self.groupBox)
        self.verticalLayout_5.setObjectName(_fromUtf8("verticalLayout_5"))
        self.list = QtGui.QRadioButton(self.groupBox)
        self.list.setChecked(True)
        self.list.setObjectName(_fromUtf8("list"))
        self.verticalLayout_5.addWidget(self.list)
        self.current = QtGui.QRadioButton(self.groupBox)
        self.current.setObjectName(_fromUtf8("current"))
        self.verticalLayout_5.addWidget(self.current)
        self.selected = QtGui.QRadioButton(self.groupBox)
        self.selected.setObjectName(_fromUtf8("selected"))
        self.verticalLayout_5.addWidget(self.selected)
        self.verticalLayout_2.addWidget(self.groupBox)
        self.groupBox_2 = QtGui.QGroupBox(self.wizardPage)
        self.groupBox_2.setObjectName(_fromUtf8("groupBox_2"))
        self.verticalLayout = QtGui.QVBoxLayout(self.groupBox_2)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.group_type = QtGui.QRadioButton(self.groupBox_2)
        self.group_type.setChecked(True)
        self.group_type.setObjectName(_fromUtf8("group_type"))
        self.verticalLayout.addWidget(self.group_type)
        self.group_module = QtGui.QRadioButton(self.groupBox_2)
        self.group_module.setObjectName(_fromUtf8("group_module"))
        self.verticalLayout.addWidget(self.group_module)
        self.verticalLayout_2.addWidget(self.groupBox_2)
        SelectAttributesWiz.addPage(self.wizardPage)
        self.wizardPage1 = QtGui.QWizardPage()
        self.wizardPage1.setObjectName(_fromUtf8("wizardPage1"))
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.wizardPage1)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.label_3 = QtGui.QLabel(self.wizardPage1)
        self.label_3.setText(_fromUtf8(""))
        self.label_3.setPixmap(QtGui.QPixmap(_fromUtf8(":/menuedit")))
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.horizontalLayout_2.addWidget(self.label_3)
        self.label_4 = QtGui.QLabel(self.wizardPage1)
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.horizontalLayout_2.addWidget(self.label_4)
        self.horizontalLayout_2.setStretch(1, 100)
        self.verticalLayout_3.addLayout(self.horizontalLayout_2)
        self.currentnode = QtGui.QLabel(self.wizardPage1)
        self.currentnode.setText(_fromUtf8(""))
        self.currentnode.setObjectName(_fromUtf8("currentnode"))
        self.verticalLayout_3.addWidget(self.currentnode)
        self.progress = QtGui.QProgressBar(self.wizardPage1)
        self.progress.setProperty("value", 0)
        self.progress.setObjectName(_fromUtf8("progress"))
        self.verticalLayout_3.addWidget(self.progress)
        self.label_3.raise_()
        self.label_3.raise_()
        self.progress.raise_()
        self.currentnode.raise_()
        SelectAttributesWiz.addPage(self.wizardPage1)
        self.wizardPage_2 = QtGui.QWizardPage()
        self.wizardPage_2.setObjectName(_fromUtf8("wizardPage_2"))
        self.verticalLayout_4 = QtGui.QVBoxLayout(self.wizardPage_2)
        self.verticalLayout_4.setObjectName(_fromUtf8("verticalLayout_4"))
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.label_5 = QtGui.QLabel(self.wizardPage_2)
        self.label_5.setText(_fromUtf8(""))
        self.label_5.setPixmap(QtGui.QPixmap(_fromUtf8(":/menuedit")))
        self.label_5.setObjectName(_fromUtf8("label_5"))
        self.horizontalLayout_3.addWidget(self.label_5)
        self.label_6 = QtGui.QLabel(self.wizardPage_2)
        self.label_6.setObjectName(_fromUtf8("label_6"))
        self.horizontalLayout_3.addWidget(self.label_6)
        self.horizontalLayout_3.setStretch(1, 100)
        self.verticalLayout_4.addLayout(self.horizontalLayout_3)
        self.tabWidget = QtGui.QTabWidget(self.wizardPage_2)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.verticalLayout_4.addWidget(self.tabWidget)
        SelectAttributesWiz.addPage(self.wizardPage_2)

        self.retranslateUi(SelectAttributesWiz)
        self.tabWidget.setCurrentIndex(-1)
        QtCore.QMetaObject.connectSlotsByName(SelectAttributesWiz)

    def retranslateUi(self, SelectAttributesWiz):
        SelectAttributesWiz.setWindowTitle(_translate("SelectAttributesWiz", "Select attributes", None))
        self.label_2.setText(_translate("SelectAttributesWiz", "Attribute selection location", None))
        self.groupBox.setTitle(_translate("SelectAttributesWiz", "Select attributes from", None))
        self.list.setText(_translate("SelectAttributesWiz", "Current list", None))
        self.current.setText(_translate("SelectAttributesWiz", "Current selected file", None))
        self.selected.setText(_translate("SelectAttributesWiz", "All selected files", None))
        self.groupBox_2.setTitle(_translate("SelectAttributesWiz", "Group attributes by", None))
        self.group_type.setText(_translate("SelectAttributesWiz", "Types", None))
        self.group_module.setText(_translate("SelectAttributesWiz", "Generated module", None))
        self.label_4.setText(_translate("SelectAttributesWiz", "Gathering list of attributes", None))
        self.label_6.setText(_translate("SelectAttributesWiz", "Select attributes", None))

import gui_rc

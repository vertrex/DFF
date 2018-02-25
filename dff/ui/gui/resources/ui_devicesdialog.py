# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/devicesdialog.ui'
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

class Ui_DevicesDialog(object):
    def setupUi(self, DevicesDialog):
        DevicesDialog.setObjectName(_fromUtf8("DevicesDialog"))
        DevicesDialog.resize(500, 300)
        self.verticalLayout = QtGui.QVBoxLayout(DevicesDialog)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.label_2 = QtGui.QLabel(DevicesDialog)
        self.label_2.setMaximumSize(QtCore.QSize(127, 127))
        self.label_2.setText(_fromUtf8(""))
        self.label_2.setPixmap(QtGui.QPixmap(_fromUtf8(":/add_device.png")))
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.horizontalLayout.addWidget(self.label_2)
        self.label = QtGui.QLabel(DevicesDialog)
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayout.addWidget(self.label)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.label_3 = QtGui.QLabel(DevicesDialog)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.verticalLayout.addWidget(self.label_3)
        self.gridLayout = QtGui.QGridLayout()
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.ldevice = QtGui.QLabel(DevicesDialog)
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        self.ldevice.setFont(font)
        self.ldevice.setObjectName(_fromUtf8("ldevice"))
        self.gridLayout.addWidget(self.ldevice, 0, 0, 1, 1)
        self.combodevice = QtGui.QComboBox(DevicesDialog)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.combodevice.setFont(font)
        self.combodevice.setObjectName(_fromUtf8("combodevice"))
        self.gridLayout.addWidget(self.combodevice, 0, 1, 1, 1)
        self.lblockname = QtGui.QLabel(DevicesDialog)
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        self.lblockname.setFont(font)
        self.lblockname.setObjectName(_fromUtf8("lblockname"))
        self.gridLayout.addWidget(self.lblockname, 1, 0, 1, 1)
        self.blockdevice = QtGui.QLabel(DevicesDialog)
        self.blockdevice.setObjectName(_fromUtf8("blockdevice"))
        self.gridLayout.addWidget(self.blockdevice, 1, 1, 1, 1)
        self.lmodel = QtGui.QLabel(DevicesDialog)
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        self.lmodel.setFont(font)
        self.lmodel.setObjectName(_fromUtf8("lmodel"))
        self.gridLayout.addWidget(self.lmodel, 2, 0, 1, 1)
        self.model = QtGui.QLabel(DevicesDialog)
        self.model.setObjectName(_fromUtf8("model"))
        self.gridLayout.addWidget(self.model, 2, 1, 1, 1)
        self.lserial = QtGui.QLabel(DevicesDialog)
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        self.lserial.setFont(font)
        self.lserial.setObjectName(_fromUtf8("lserial"))
        self.gridLayout.addWidget(self.lserial, 3, 0, 1, 1)
        self.serial = QtGui.QLabel(DevicesDialog)
        self.serial.setObjectName(_fromUtf8("serial"))
        self.gridLayout.addWidget(self.serial, 3, 1, 1, 1)
        self.lsize = QtGui.QLabel(DevicesDialog)
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        self.lsize.setFont(font)
        self.lsize.setObjectName(_fromUtf8("lsize"))
        self.gridLayout.addWidget(self.lsize, 4, 0, 1, 1)
        self.size = QtGui.QLabel(DevicesDialog)
        self.size.setObjectName(_fromUtf8("size"))
        self.gridLayout.addWidget(self.size, 4, 1, 1, 1)
        self.label_4 = QtGui.QLabel(DevicesDialog)
        self.label_4.setText(_fromUtf8(""))
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.gridLayout.addWidget(self.label_4, 5, 0, 1, 1)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem, 5, 1, 1, 1)
        self.verticalLayout.addLayout(self.gridLayout)
        self.buttonBox = QtGui.QDialogButtonBox(DevicesDialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.verticalLayout.addWidget(self.buttonBox)

        self.retranslateUi(DevicesDialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), DevicesDialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), DevicesDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(DevicesDialog)

    def retranslateUi(self, DevicesDialog):
        DevicesDialog.setWindowTitle(_translate("DevicesDialog", "Select Device", None))
        self.label.setText(_translate("DevicesDialog", "Select a local device to add in the Virtual File System", None))
        self.label_3.setText(_translate("DevicesDialog", "Warning : You must run the software with Administrator rights", None))
        self.ldevice.setText(_translate("DevicesDialog", "Device", None))
        self.lblockname.setText(_translate("DevicesDialog", "Block device name", None))
        self.lmodel.setText(_translate("DevicesDialog", "Model", None))
        self.lserial.setText(_translate("DevicesDialog", "Serial", None))
        self.lsize.setText(_translate("DevicesDialog", "Size", None))

import gui_rc

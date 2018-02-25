# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/status.ui'
#
# Created: Sat Feb 15 22:45:18 2014
#      by: PyQt4 UI code generator 4.10.2
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

class Ui_StatusBar(object):
    def setupUi(self, StatusBar):
        StatusBar.setObjectName(_fromUtf8("StatusBar"))
        StatusBar.setEnabled(True)
        StatusBar.resize(728, 16)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(StatusBar.sizePolicy().hasHeightForWidth())
        StatusBar.setSizePolicy(sizePolicy)
        StatusBar.setMinimumSize(QtCore.QSize(16, 16))
        font = QtGui.QFont()
        font.setPointSize(8)
        StatusBar.setFont(font)
        self.hlayout = QtGui.QHBoxLayout(StatusBar)
        self.hlayout.setSpacing(6)
        self.hlayout.setSizeConstraint(QtGui.QLayout.SetNoConstraint)
        self.hlayout.setMargin(0)
        self.hlayout.setObjectName(_fromUtf8("hlayout"))
        self.nodeLabel = QtGui.QLabel(StatusBar)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.nodeLabel.setFont(font)
        self.nodeLabel.setObjectName(_fromUtf8("nodeLabel"))
        self.hlayout.addWidget(self.nodeLabel)
        self.nodesStatus = QtGui.QLabel(StatusBar)
        self.nodesStatus.setObjectName(_fromUtf8("nodesStatus"))
        self.hlayout.addWidget(self.nodesStatus)
        self.line1 = QtGui.QFrame(StatusBar)
        self.line1.setFrameShape(QtGui.QFrame.VLine)
        self.line1.setFrameShadow(QtGui.QFrame.Sunken)
        self.line1.setObjectName(_fromUtf8("line1"))
        self.hlayout.addWidget(self.line1)
        self.filesLabel = QtGui.QLabel(StatusBar)
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setBold(True)
        font.setWeight(75)
        self.filesLabel.setFont(font)
        self.filesLabel.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.filesLabel.setObjectName(_fromUtf8("filesLabel"))
        self.hlayout.addWidget(self.filesLabel)
        self.filesStatus = QtGui.QLabel(StatusBar)
        self.filesStatus.setObjectName(_fromUtf8("filesStatus"))
        self.hlayout.addWidget(self.filesStatus)
        self.line2 = QtGui.QFrame(StatusBar)
        self.line2.setFrameShape(QtGui.QFrame.VLine)
        self.line2.setFrameShadow(QtGui.QFrame.Sunken)
        self.line2.setObjectName(_fromUtf8("line2"))
        self.hlayout.addWidget(self.line2)
        self.foldersLabel = QtGui.QLabel(StatusBar)
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setBold(True)
        font.setWeight(75)
        self.foldersLabel.setFont(font)
        self.foldersLabel.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse|QtCore.Qt.TextSelectableByMouse)
        self.foldersLabel.setObjectName(_fromUtf8("foldersLabel"))
        self.hlayout.addWidget(self.foldersLabel)
        self.foldersStatus = QtGui.QLabel(StatusBar)
        self.foldersStatus.setObjectName(_fromUtf8("foldersStatus"))
        self.hlayout.addWidget(self.foldersStatus)
        self.line3 = QtGui.QFrame(StatusBar)
        self.line3.setFrameShape(QtGui.QFrame.VLine)
        self.line3.setFrameShadow(QtGui.QFrame.Sunken)
        self.line3.setObjectName(_fromUtf8("line3"))
        self.hlayout.addWidget(self.line3)
        self.selectedLabel = QtGui.QLabel(StatusBar)
        font = QtGui.QFont()
        font.setPointSize(8)
        font.setBold(True)
        font.setWeight(75)
        self.selectedLabel.setFont(font)
        self.selectedLabel.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.selectedLabel.setObjectName(_fromUtf8("selectedLabel"))
        self.hlayout.addWidget(self.selectedLabel)
        self.selectedStatus = QtGui.QLabel(StatusBar)
        font = QtGui.QFont()
        font.setPointSize(8)
        self.selectedStatus.setFont(font)
        self.selectedStatus.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByMouse)
        self.selectedStatus.setObjectName(_fromUtf8("selectedStatus"))
        self.hlayout.addWidget(self.selectedStatus)
        self.line = QtGui.QFrame(StatusBar)
        self.line.setFrameShape(QtGui.QFrame.VLine)
        self.line.setFrameShadow(QtGui.QFrame.Sunken)
        self.line.setObjectName(_fromUtf8("line"))
        self.hlayout.addWidget(self.line)
        self.totalBytes = QtGui.QLabel(StatusBar)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.totalBytes.setFont(font)
        self.totalBytes.setObjectName(_fromUtf8("totalBytes"))
        self.hlayout.addWidget(self.totalBytes)
        self.totalBytesCount = QtGui.QLabel(StatusBar)
        self.totalBytesCount.setObjectName(_fromUtf8("totalBytesCount"))
        self.hlayout.addWidget(self.totalBytesCount)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.hlayout.addItem(spacerItem)

        self.retranslateUi(StatusBar)
        QtCore.QMetaObject.connectSlotsByName(StatusBar)

    def retranslateUi(self, StatusBar):
        StatusBar.setWindowTitle(_translate("StatusBar", "Status", None))
        self.nodeLabel.setText(_translate("StatusBar", "Nodes", None))
        self.nodesStatus.setText(_translate("StatusBar", "-", None))
        self.filesLabel.setText(_translate("StatusBar", "Files", None))
        self.filesStatus.setText(_translate("StatusBar", "-", None))
        self.foldersLabel.setText(_translate("StatusBar", "Folders", None))
        self.foldersStatus.setText(_translate("StatusBar", "-", None))
        self.selectedLabel.setText(_translate("StatusBar", "Selected", None))
        self.selectedStatus.setToolTip(_translate("StatusBar", "Total number of selected items for this browser", None))
        self.selectedStatus.setText(_translate("StatusBar", "0", None))
        self.totalBytes.setText(_translate("StatusBar", "Total bytes", None))
        self.totalBytesCount.setText(_translate("StatusBar", "0", None))


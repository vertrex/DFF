# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/taskmanager.ui'
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

class Ui_TaskManager(object):
    def setupUi(self, TaskManager):
        TaskManager.setObjectName(_fromUtf8("TaskManager"))
        TaskManager.resize(256, 192)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(TaskManager.sizePolicy().hasHeightForWidth())
        TaskManager.setSizePolicy(sizePolicy)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/script-run.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        TaskManager.setWindowIcon(icon)
        self.useless = QtGui.QWidget(TaskManager)
        self.useless.setEnabled(False)
        self.useless.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.useless.setObjectName(_fromUtf8("useless"))

        self.retranslateUi(TaskManager)
        QtCore.QMetaObject.connectSlotsByName(TaskManager)

    def retranslateUi(self, TaskManager):
        TaskManager.setWindowTitle(_translate("TaskManager", "Task Manager", None))
        TaskManager.headerItem().setText(0, _translate("TaskManager", "PID", None))
        TaskManager.headerItem().setText(1, _translate("TaskManager", "Name", None))
        TaskManager.headerItem().setText(2, _translate("TaskManager", "State", None))
        TaskManager.headerItem().setText(3, _translate("TaskManager", "Info", None))
        TaskManager.headerItem().setText(4, _translate("TaskManager", "Duration", None))

import gui_rc

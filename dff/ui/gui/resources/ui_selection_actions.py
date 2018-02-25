# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/selection_actions.ui'
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

class Ui_selectionActions(object):
    def setupUi(self, selectionActions):
        selectionActions.setObjectName(_fromUtf8("selectionActions"))
        selectionActions.resize(400, 300)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/view_detailed.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        selectionActions.setWindowIcon(icon)
        self.actionSelect_all = QtGui.QAction(selectionActions)
        self.actionSelect_all.setObjectName(_fromUtf8("actionSelect_all"))
        self.actionUnselect_all = QtGui.QAction(selectionActions)
        self.actionUnselect_all.setObjectName(_fromUtf8("actionUnselect_all"))
        self.actionClear_selection = QtGui.QAction(selectionActions)
        self.actionClear_selection.setObjectName(_fromUtf8("actionClear_selection"))

        self.retranslateUi(selectionActions)
        QtCore.QMetaObject.connectSlotsByName(selectionActions)

    def retranslateUi(self, selectionActions):
        selectionActions.setWindowTitle(_translate("selectionActions", "Browser", None))
        self.actionSelect_all.setText(_translate("selectionActions", "Select all", None))
        self.actionUnselect_all.setText(_translate("selectionActions", "Unselect all", None))
        self.actionClear_selection.setText(_translate("selectionActions", "Clear selection", None))

import gui_rc

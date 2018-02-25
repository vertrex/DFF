# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/nodeactions.ui'
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

class Ui_nodeActions(object):
    def setupUi(self, nodeActions):
        nodeActions.setObjectName(_fromUtf8("nodeActions"))
        nodeActions.resize(400, 297)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/view_detailed.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        nodeActions.setWindowIcon(icon)
        self.actionOpen_in_new_tab = QtGui.QAction(nodeActions)
        self.actionOpen_in_new_tab.setEnabled(False)
        self.actionOpen_in_new_tab.setObjectName(_fromUtf8("actionOpen_in_new_tab"))
        self.actionOpen = QtGui.QAction(nodeActions)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8(":/exec.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionOpen.setIcon(icon1)
        self.actionOpen.setIconVisibleInMenu(True)
        self.actionOpen.setObjectName(_fromUtf8("actionOpen"))
        self.actionOpen_with = QtGui.QAction(nodeActions)
        self.actionOpen_with.setIcon(icon1)
        self.actionOpen_with.setIconVisibleInMenu(True)
        self.actionOpen_with.setObjectName(_fromUtf8("actionOpen_with"))
        self.actionHex_viewer = QtGui.QAction(nodeActions)
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(_fromUtf8(":/hexedit.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionHex_viewer.setIcon(icon2)
        self.actionHex_viewer.setIconVisibleInMenu(True)
        self.actionHex_viewer.setObjectName(_fromUtf8("actionHex_viewer"))
        self.actionExtract = QtGui.QAction(nodeActions)
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(_fromUtf8(":/extract.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionExtract.setIcon(icon3)
        self.actionExtract.setIconVisibleInMenu(True)
        self.actionExtract.setObjectName(_fromUtf8("actionExtract"))
        self.actionRelevant_module = QtGui.QAction(nodeActions)
        self.actionRelevant_module.setObjectName(_fromUtf8("actionRelevant_module"))
        self.actionBookmark = QtGui.QAction(nodeActions)
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(_fromUtf8(":/bookmark_add.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionBookmark.setIcon(icon4)
        self.actionBookmark.setObjectName(_fromUtf8("actionBookmark"))
        self.actionOpen_parent_folder = QtGui.QAction(nodeActions)
        self.actionOpen_parent_folder.setObjectName(_fromUtf8("actionOpen_parent_folder"))
        self.actionTags = QtGui.QAction(nodeActions)
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap(_fromUtf8(":/tag")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionTags.setIcon(icon5)
        self.actionTags.setObjectName(_fromUtf8("actionTags"))

        self.retranslateUi(nodeActions)
        QtCore.QMetaObject.connectSlotsByName(nodeActions)

    def retranslateUi(self, nodeActions):
        nodeActions.setWindowTitle(_translate("nodeActions", "Browser", None))
        self.actionOpen_in_new_tab.setText(_translate("nodeActions", "Open in new tab", None))
        self.actionOpen.setText(_translate("nodeActions", "Open", None))
        self.actionOpen_with.setText(_translate("nodeActions", "Open with", None))
        self.actionHex_viewer.setText(_translate("nodeActions", "Hex viewer", None))
        self.actionExtract.setText(_translate("nodeActions", "Extract", None))
        self.actionRelevant_module.setText(_translate("nodeActions", "Relevant module", None))
        self.actionBookmark.setText(_translate("nodeActions", "Bookmark", None))
        self.actionBookmark.setToolTip(_translate("nodeActions", "Add nodes to bookmark", None))
        self.actionOpen_parent_folder.setText(_translate("nodeActions", "Open parent folder", None))
        self.actionOpen_parent_folder.setToolTip(_translate("nodeActions", "Open parent folder", None))
        self.actionTags.setText(_translate("nodeActions", "Tags", None))
        self.actionTags.setToolTip(_translate("nodeActions", "Tag nodes", None))

import gui_rc

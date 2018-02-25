# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/ide.ui'
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

class Ui_Ide(object):
    def setupUi(self, Ide):
        Ide.setObjectName(_fromUtf8("Ide"))
        Ide.resize(770, 405)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/ide.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        Ide.setWindowIcon(icon)
        self.vbox = QtGui.QVBoxLayout(Ide)
        self.vbox.setMargin(0)
        self.vbox.setSpacing(0)
        self.vbox.setObjectName(_fromUtf8("vbox"))
        self.toolbar = QtGui.QToolBar(Ide)
        self.toolbar.setObjectName(_fromUtf8("toolbar"))
        self.vbox.addWidget(self.toolbar)
        self.newemptyact = QtGui.QAction(Ide)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8(":/empty.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.newemptyact.setIcon(icon1)
        self.newemptyact.setIconVisibleInMenu(True)
        self.newemptyact.setObjectName(_fromUtf8("newemptyact"))
        self.newact = QtGui.QAction(Ide)
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(_fromUtf8(":/script-new.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.newact.setIcon(icon2)
        self.newact.setIconVisibleInMenu(True)
        self.newact.setObjectName(_fromUtf8("newact"))
        self.openact = QtGui.QAction(Ide)
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(_fromUtf8(":/script-open.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.openact.setIcon(icon3)
        self.openact.setIconVisibleInMenu(True)
        self.openact.setObjectName(_fromUtf8("openact"))
        self.saveact = QtGui.QAction(Ide)
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(_fromUtf8(":/script-save.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.saveact.setIcon(icon4)
        self.saveact.setIconVisibleInMenu(True)
        self.saveact.setObjectName(_fromUtf8("saveact"))
        self.saveasact = QtGui.QAction(Ide)
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap(_fromUtf8(":/script-save-as.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.saveasact.setIcon(icon5)
        self.saveasact.setIconVisibleInMenu(True)
        self.saveasact.setObjectName(_fromUtf8("saveasact"))
        self.runact = QtGui.QAction(Ide)
        icon6 = QtGui.QIcon()
        icon6.addPixmap(QtGui.QPixmap(_fromUtf8(":/script-run.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.runact.setIcon(icon6)
        self.runact.setIconVisibleInMenu(True)
        self.runact.setObjectName(_fromUtf8("runact"))
        self.undoact = QtGui.QAction(Ide)
        icon7 = QtGui.QIcon()
        icon7.addPixmap(QtGui.QPixmap(_fromUtf8(":/undo.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.undoact.setIcon(icon7)
        self.undoact.setIconVisibleInMenu(True)
        self.undoact.setObjectName(_fromUtf8("undoact"))
        self.redoact = QtGui.QAction(Ide)
        icon8 = QtGui.QIcon()
        icon8.addPixmap(QtGui.QPixmap(_fromUtf8(":/redo.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.redoact.setIcon(icon8)
        self.redoact.setIconVisibleInMenu(True)
        self.redoact.setObjectName(_fromUtf8("redoact"))
        self.commentact = QtGui.QAction(Ide)
        icon9 = QtGui.QIcon()
        icon9.addPixmap(QtGui.QPixmap(_fromUtf8(":/comment.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.commentact.setIcon(icon9)
        self.commentact.setIconVisibleInMenu(True)
        self.commentact.setObjectName(_fromUtf8("commentact"))
        self.uncommentact = QtGui.QAction(Ide)
        icon10 = QtGui.QIcon()
        icon10.addPixmap(QtGui.QPixmap(_fromUtf8(":/uncomment.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.uncommentact.setIcon(icon10)
        self.uncommentact.setIconVisibleInMenu(True)
        self.uncommentact.setObjectName(_fromUtf8("uncommentact"))
        self.toolbar.addAction(self.newemptyact)
        self.toolbar.addAction(self.newact)
        self.toolbar.addAction(self.openact)
        self.toolbar.addAction(self.saveact)
        self.toolbar.addAction(self.saveasact)
        self.toolbar.addAction(self.runact)
        self.toolbar.addAction(self.undoact)
        self.toolbar.addAction(self.redoact)
        self.toolbar.addAction(self.commentact)
        self.toolbar.addAction(self.uncommentact)

        self.retranslateUi(Ide)
        QtCore.QMetaObject.connectSlotsByName(Ide)

    def retranslateUi(self, Ide):
        Ide.setWindowTitle(_translate("Ide", "IDE", None))
        self.toolbar.setWindowTitle(_translate("Ide", "IDE toolbar", None))
        self.newemptyact.setText(_translate("Ide", "New empty file", None))
        self.newact.setText(_translate("Ide", "Generate skeleton", None))
        self.openact.setText(_translate("Ide", "Open file", None))
        self.saveact.setText(_translate("Ide", "Save", None))
        self.saveasact.setText(_translate("Ide", "Save as", None))
        self.runact.setText(_translate("Ide", "Load", None))
        self.undoact.setText(_translate("Ide", "Undo", None))
        self.redoact.setText(_translate("Ide", "Redo", None))
        self.commentact.setText(_translate("Ide", "Comment", None))
        self.uncommentact.setText(_translate("Ide", "Uncomment", None))

import gui_rc

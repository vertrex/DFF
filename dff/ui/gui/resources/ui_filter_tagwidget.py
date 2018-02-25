# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/filter_tagwidget.ui'
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

class Ui_filterTagwidget(object):
    def setupUi(self, filterTagwidget):
        filterTagwidget.setObjectName(_fromUtf8("filterTagwidget"))
        filterTagwidget.resize(640, 22)
        self.horizontalLayout = QtGui.QHBoxLayout(filterTagwidget)
        self.horizontalLayout.setMargin(0)
        self.horizontalLayout.setSpacing(0)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.exclude = QtGui.QCheckBox(filterTagwidget)
        self.exclude.setObjectName(_fromUtf8("exclude"))
        self.horizontalLayout.addWidget(self.exclude)

        self.retranslateUi(filterTagwidget)
        QtCore.QMetaObject.connectSlotsByName(filterTagwidget)

    def retranslateUi(self, filterTagwidget):
        filterTagwidget.setWindowTitle(_translate("filterTagwidget", "Form", None))
        self.exclude.setText(_translate("filterTagwidget", "Exclude", None))


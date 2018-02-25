# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/browser_toolbar.ui'
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

class Ui_BrowserToolBar(object):
    def setupUi(self, BrowserToolBar):
        BrowserToolBar.setObjectName(_fromUtf8("BrowserToolBar"))
        BrowserToolBar.resize(666, 33)
        self.changeView = QtGui.QComboBox(BrowserToolBar)
        self.changeView.setGeometry(QtCore.QRect(1, 3, 103, 27))
        self.changeView.setObjectName(_fromUtf8("changeView"))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/view_detailed.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.changeView.addItem(icon, _fromUtf8(""))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8(":/view_icon.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.changeView.addItem(icon1, _fromUtf8(""))
        self.tags = QtGui.QToolButton(BrowserToolBar)
        self.tags.setGeometry(QtCore.QRect(198, 1, 71, 32))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(_fromUtf8(":/highlight")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.tags.setIcon(icon2)
        self.tags.setPopupMode(QtGui.QToolButton.InstantPopup)
        self.tags.setToolButtonStyle(QtCore.Qt.ToolButtonTextBesideIcon)
        self.tags.setAutoRaise(True)
        self.tags.setArrowType(QtCore.Qt.NoArrow)
        self.tags.setObjectName(_fromUtf8("tags"))
        self.search = QtGui.QPushButton(BrowserToolBar)
        self.search.setGeometry(QtCore.QRect(275, 1, 88, 32))
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(_fromUtf8(":/search_small.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.search.setIcon(icon3)
        self.search.setCheckable(True)
        self.search.setFlat(False)
        self.search.setObjectName(_fromUtf8("search"))
        self.factorSlider = QtGui.QSlider(BrowserToolBar)
        self.factorSlider.setGeometry(QtCore.QRect(120, 10, 50, 24))
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.factorSlider.sizePolicy().hasHeightForWidth())
        self.factorSlider.setSizePolicy(sizePolicy)
        self.factorSlider.setBaseSize(QtCore.QSize(80, 0))
        self.factorSlider.setMinimum(1)
        self.factorSlider.setMaximum(4)
        self.factorSlider.setOrientation(QtCore.Qt.Horizontal)
        self.factorSlider.setTickPosition(QtGui.QSlider.TicksAbove)
        self.factorSlider.setTickInterval(1)
        self.factorSlider.setObjectName(_fromUtf8("factorSlider"))
        self.filter = QtGui.QPushButton(BrowserToolBar)
        self.filter.setGeometry(QtCore.QRect(370, 0, 111, 32))
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(_fromUtf8(":/filter")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.filter.setIcon(icon4)
        self.filter.setCheckable(True)
        self.filter.setFlat(False)
        self.filter.setObjectName(_fromUtf8("filter"))
        self.actionAttributes = QtGui.QAction(BrowserToolBar)
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap(_fromUtf8(":/menuedit")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionAttributes.setIcon(icon5)
        self.actionAttributes.setObjectName(_fromUtf8("actionAttributes"))
        self.actionBookmark = QtGui.QAction(BrowserToolBar)
        icon6 = QtGui.QIcon()
        icon6.addPixmap(QtGui.QPixmap(_fromUtf8(":/bookmark_add.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionBookmark.setIcon(icon6)
        self.actionBookmark.setObjectName(_fromUtf8("actionBookmark"))
        self.actionFactorPlus = QtGui.QAction(BrowserToolBar)
        icon7 = QtGui.QIcon()
        icon7.addPixmap(QtGui.QPixmap(_fromUtf8(":/viewmag+")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionFactorPlus.setIcon(icon7)
        self.actionFactorPlus.setObjectName(_fromUtf8("actionFactorPlus"))
        self.actionFactorMinus = QtGui.QAction(BrowserToolBar)
        icon8 = QtGui.QIcon()
        icon8.addPixmap(QtGui.QPixmap(_fromUtf8(":/viewmag-")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionFactorMinus.setIcon(icon8)
        self.actionFactorMinus.setObjectName(_fromUtf8("actionFactorMinus"))

        self.retranslateUi(BrowserToolBar)
        QtCore.QMetaObject.connectSlotsByName(BrowserToolBar)

    def retranslateUi(self, BrowserToolBar):
        BrowserToolBar.setWindowTitle(_translate("BrowserToolBar", "Browser", None))
        self.changeView.setItemText(0, _translate("BrowserToolBar", "Details", None))
        self.changeView.setItemText(1, _translate("BrowserToolBar", "Icons", None))
        self.tags.setText(_translate("BrowserToolBar", "Tags", None))
        self.search.setText(_translate("BrowserToolBar", "Search", None))
        self.filter.setText(_translate("BrowserToolBar", "Filter", None))
        self.actionAttributes.setText(_translate("BrowserToolBar", "attributes", None))
        self.actionAttributes.setToolTip(_translate("BrowserToolBar", "Edit attributes to display as column in the detailed view", None))
        self.actionBookmark.setText(_translate("BrowserToolBar", "bookmark", None))
        self.actionBookmark.setToolTip(_translate("BrowserToolBar", "Add nodes to bookmark", None))
        self.actionFactorPlus.setText(_translate("BrowserToolBar", "factorPlus", None))
        self.actionFactorPlus.setToolTip(_translate("BrowserToolBar", "Icons zoom in", None))
        self.actionFactorMinus.setText(_translate("BrowserToolBar", "factorMinus", None))
        self.actionFactorMinus.setToolTip(_translate("BrowserToolBar", "Icons zoom out", None))

import gui_rc

# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/vertrex/dff-pro/dff/ui/gui/resources/tags.ui'
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

class Ui_Tags(object):
    def setupUi(self, Tags):
        Tags.setObjectName(_fromUtf8("Tags"))
        Tags.resize(581, 373)
        self.gridLayout = QtGui.QGridLayout(Tags)
        self.gridLayout.setSizeConstraint(QtGui.QLayout.SetDefaultConstraint)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.horizontalLayout_21 = QtGui.QHBoxLayout()
        self.horizontalLayout_21.setSizeConstraint(QtGui.QLayout.SetFixedSize)
        self.horizontalLayout_21.setObjectName(_fromUtf8("horizontalLayout_21"))
        self.label_11 = QtGui.QLabel(Tags)
        self.label_11.setText(_fromUtf8(""))
        self.label_11.setPixmap(QtGui.QPixmap(_fromUtf8(":/tag")))
        self.label_11.setObjectName(_fromUtf8("label_11"))
        self.horizontalLayout_21.addWidget(self.label_11)
        self.verticalLayout_26 = QtGui.QVBoxLayout()
        self.verticalLayout_26.setObjectName(_fromUtf8("verticalLayout_26"))
        self.label_12 = QtGui.QLabel(Tags)
        self.label_12.setObjectName(_fromUtf8("label_12"))
        self.verticalLayout_26.addWidget(self.label_12)
        spacerItem = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout_26.addItem(spacerItem)
        self.horizontalLayout_21.addLayout(self.verticalLayout_26)
        self.gridLayout.addLayout(self.horizontalLayout_21, 0, 0, 1, 1)
        self.groupBox = QtGui.QGroupBox(Tags)
        self.groupBox.setAutoFillBackground(True)
        self.groupBox.setFlat(False)
        self.groupBox.setCheckable(False)
        self.groupBox.setObjectName(_fromUtf8("groupBox"))
        self.verticalLayout_29 = QtGui.QVBoxLayout(self.groupBox)
        self.verticalLayout_29.setObjectName(_fromUtf8("verticalLayout_29"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.selectedLabel = QtGui.QLabel(self.groupBox)
        self.selectedLabel.setObjectName(_fromUtf8("selectedLabel"))
        self.horizontalLayout.addWidget(self.selectedLabel)
        self.availableLabel = QtGui.QLabel(self.groupBox)
        self.availableLabel.setObjectName(_fromUtf8("availableLabel"))
        self.horizontalLayout.addWidget(self.availableLabel)
        self.horizontalLayout.setStretch(0, 1)
        self.verticalLayout_29.addLayout(self.horizontalLayout)
        self.horizontalLayout_23 = QtGui.QHBoxLayout()
        self.horizontalLayout_23.setObjectName(_fromUtf8("horizontalLayout_23"))
        self.selectedTags = QtGui.QListWidget(self.groupBox)
        self.selectedTags.setObjectName(_fromUtf8("selectedTags"))
        self.horizontalLayout_23.addWidget(self.selectedTags)
        self.verticalLayout_30 = QtGui.QVBoxLayout()
        self.verticalLayout_30.setObjectName(_fromUtf8("verticalLayout_30"))
        self.addTagNodesButton = QtGui.QPushButton(self.groupBox)
        self.addTagNodesButton.setText(_fromUtf8("<<"))
        self.addTagNodesButton.setObjectName(_fromUtf8("addTagNodesButton"))
        self.verticalLayout_30.addWidget(self.addTagNodesButton)
        self.removeTagNodesButton = QtGui.QPushButton(self.groupBox)
        self.removeTagNodesButton.setText(_fromUtf8(">>"))
        self.removeTagNodesButton.setObjectName(_fromUtf8("removeTagNodesButton"))
        self.verticalLayout_30.addWidget(self.removeTagNodesButton)
        self.newTagButton = QtGui.QPushButton(self.groupBox)
        self.newTagButton.setText(_fromUtf8("New"))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/add.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.newTagButton.setIcon(icon)
        self.newTagButton.setObjectName(_fromUtf8("newTagButton"))
        self.verticalLayout_30.addWidget(self.newTagButton)
        self.deleteTagButton = QtGui.QPushButton(self.groupBox)
        self.deleteTagButton.setText(_fromUtf8("Delete"))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8(":/cancel.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.deleteTagButton.setIcon(icon1)
        self.deleteTagButton.setObjectName(_fromUtf8("deleteTagButton"))
        self.verticalLayout_30.addWidget(self.deleteTagButton)
        spacerItem1 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout_30.addItem(spacerItem1)
        self.horizontalLayout_23.addLayout(self.verticalLayout_30)
        self.allTags = QtGui.QListWidget(self.groupBox)
        self.allTags.setObjectName(_fromUtf8("allTags"))
        self.horizontalLayout_23.addWidget(self.allTags)
        self.verticalLayout_29.addLayout(self.horizontalLayout_23)
        self.gridLayout.addWidget(self.groupBox, 1, 0, 1, 1)
        self.buttonBox_6 = QtGui.QDialogButtonBox(Tags)
        self.buttonBox_6.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox_6.setStandardButtons(QtGui.QDialogButtonBox.Ok)
        self.buttonBox_6.setObjectName(_fromUtf8("buttonBox_6"))
        self.gridLayout.addWidget(self.buttonBox_6, 2, 0, 1, 1)

        self.retranslateUi(Tags)
        QtCore.QObject.connect(self.buttonBox_6, QtCore.SIGNAL(_fromUtf8("accepted()")), Tags.accept)
        QtCore.QObject.connect(self.buttonBox_6, QtCore.SIGNAL(_fromUtf8("rejected()")), Tags.reject)
        QtCore.QMetaObject.connectSlotsByName(Tags)

    def retranslateUi(self, Tags):
        Tags.setWindowTitle(_translate("Tags", "Tags management", None))
        self.label_12.setText(_translate("Tags", "Add and remove tags from selected nodes\n"
"Add new tag or delete existing ones (Double-click to edit)", None))
        self.groupBox.setTitle(_translate("Tags", "Tags management", None))
        self.selectedLabel.setText(_translate("Tags", "Selected nodes tags", None))
        self.availableLabel.setText(_translate("Tags", "Available tags", None))

import gui_rc

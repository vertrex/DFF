# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
#  
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Frederic B. <fba@digital-forensic.org>
import string
import time
from typeSelection import filetypes
from process import CarvingProcess

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

from dff.modules.carver.utils import QFFSpinBox

class RootCheckBox(QCheckBox):
    def __init__(self):
        QCheckBox.__init__(self)
        self.children = []
        self.connect(self, SIGNAL("clicked()"), self.updateChildren)


    def addChild(self, child):
        self.children.append(child)


    def updateChildren(self):
        state = self.checkState()
        for child in self.children:
            if child.isEnabled():
                child.setCheckState(state)


    def update(self, val):
        checked = 0
        for child in self.children:
            if child.checkState() == Qt.Checked:
                checked += 1
        if checked == 0:
            self.setCheckState(Qt.Unchecked)
        elif self.checkState() == Qt.Unchecked:
            self.setCheckState(Qt.Checked)
            


class PredefinedTree(QTreeWidget):
    def __init__(self):
        QTreeWidget.__init__(self)
        self.setHeaderLabels(["Predefined patterns", "header starts at beginning of block"])
        self.typeItems = []
        self.blockAligned = []
        self.populate()


    def populate(self):
        self.connect(self, SIGNAL("itemClicked(QTreeWidgetItem *, int)"), self.clicked)
        self.connect(self, SIGNAL("itemPressed(QTreeWidgetItem *, int)"), self.clicked)
        for mimetype, mimecontent in filetypes.iteritems():
            mimetypeItem = QTreeWidgetItem(self, [mimetype])
            mimetypeItem.setFlags(Qt.ItemIsUserCheckable|Qt.ItemIsEnabled|Qt.ItemIsSelectable)
            mimetypeItem.setCheckState(0, Qt.Unchecked)
            rCheckBox = RootCheckBox()
            rCheckBox.setEnabled(False)
            self.setItemWidget(mimetypeItem, 1, rCheckBox)
            self.typeItems.append(mimetypeItem)
            for filetype, value in mimecontent.iteritems():
                filetypeItem = QTreeWidgetItem(mimetypeItem, [filetype])
                filetypeItem.setFlags(Qt.ItemIsUserCheckable|Qt.ItemIsEnabled|Qt.ItemIsSelectable)
                filetypeItem.setCheckState(0, Qt.Unchecked)
                checkBox = QCheckBox()
                checkBox.setEnabled(False)
                rCheckBox.addChild(checkBox)
                rCheckBox.connect(checkBox, SIGNAL("stateChanged(int)"), rCheckBox.update)
                self.setItemWidget(filetypeItem, 1, checkBox)
        self.resizeColumnToContents(0)


    def setCheckStateOfChildren(self, item, column, checked):
        children = item.childCount()
        for i in range(0, children):
            if checked == Qt.Checked:
                self.itemWidget(item.child(i), 1).setEnabled(True)
            else:
                self.itemWidget(item.child(i), 1).setCheckState(False)
                self.itemWidget(item.child(i), 1).setEnabled(False)
            item.child(i).setCheckState(0, checked)


    def isAllChildren(self, item, column):
        children = item.childCount()
        checked = 0
        for i in range(0, children):
            if item.child(i).checkState(column) == Qt.Checked:
                checked += 1
        if checked == 0:
            self.itemWidget(item, 1).setEnabled(False)
            item.setCheckState(0, Qt.Unchecked)
        elif item.checkState(column) == Qt.Unchecked:
            self.itemWidget(item, 1).setEnabled(True)
            item.setCheckState(0, Qt.Checked)


    def clicked(self, item, column):
        if column == 0:
            if item.childCount() != 0:
                if item.checkState(0) == Qt.Checked:
                    self.itemWidget(item, 1).setEnabled(True)
                    self.setCheckStateOfChildren(item, column, Qt.Checked)
                else:
                    self.itemWidget(item, 1).setEnabled(False)
                    self.setCheckStateOfChildren(item, column, Qt.Unchecked)
            else:
                parent = item.parent()
                if parent != None and parent.childCount() != 0:
                    self.isAllChildren(parent, column)
                if item.checkState(0) == Qt.Checked:
                    self.itemWidget(item, 1).setEnabled(True)
                else:
                    self.itemWidget(item, 1).setEnabled(False)
                    self.itemWidget(item, 1).setCheckState(False)
            

    def createGroupBox(self, items):
        gb = QGroupBox(items["type"])
        gb.setCheckable(True)
        gb.setChecked(False)
        vbox = QVBoxLayout()
        for item in items["value"]:
            button = QCheckBox(item)
            vbox.addWidget(button)
        vbox.addStretch(1)
        gb.setLayout(vbox)
        return gb


    def selectedItems(self):
        selected = {}
        for typeItem in self.typeItems:
            i = 0
            if typeItem.checkState(0) == Qt.Checked:
                mimetype = str(typeItem.text(0))
                children = typeItem.childCount()
                for i in range(0, children):
                    child = typeItem.child(i)
                    if child.checkState(0) == Qt.Checked and not child.isDisabled():
                        child.setDisabled(True)
                        text = str(child.text(0))
                        selected[text] = (filetypes[mimetype][text], self.itemWidget(child, 1).isChecked())
                        i += 1
                if i > 0:
                    typeItem.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
        return selected


class PredefinedPatterns(QWidget):
    def __init__(self, vnode):
        QWidget.__init__(self)
        self.baseLayout = QHBoxLayout(self)
        self.tree = PredefinedTree()
        self.cprocess = CarvingProcess(self.tree, vnode)
        self.baseLayout.addWidget(self.tree)
        self.baseLayout.addWidget(self.cprocess)

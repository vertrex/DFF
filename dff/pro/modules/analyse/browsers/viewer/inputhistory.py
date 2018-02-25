# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
#  Jeremy MOUNIER <jmo@digital-forensic.org>
import re

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

from dff.modules.browsers.inputhistory import Input, INPUT_HEADER
 
class InputHistoryWidget(QWidget):
    def __init__(self, inputhistory):
        QWidget.__init__(self)
        self.inputhistory = inputhistory
        self.initShape()

    def initShape(self):
        self.layout = QHBoxLayout()
        self.splitter = QSplitter()

        self.inputs = {}

        self.sources = SourceList(self)
        self.sources.updateSources(self.inputhistory.keys())

        self.values = ValueList(self)

        self.sources.connect(self.sources, 
                             SIGNAL('itemClicked(QTableWidgetItem *)'),
                             self.values.updateData)

        self.splitter.addWidget(self.sources)
        self.splitter.addWidget(self.values)

        self.layout.addWidget(self.splitter)
        self.setLayout(self.layout)


class ValueList(QTableWidget):
    def __init__(self, hmanager):
        QTableWidget.__init__(self)

        self.manager = hmanager
        self.inputhistory = hmanager.inputhistory
        self.setHeader()

    def setHeader(self):
        self.setColumnCount(len(INPUT_HEADER))
        self.setRowCount(0)
        self.horizontalHeader().setStretchLastSection(True)

        self.setSortingEnabled(False)
        self.setHorizontalHeaderLabels(INPUT_HEADER)
        self.setAlternatingRowColors(True)
#        self.setSelectionMode(QAbstractItemView.NoSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.verticalHeader().hide()

    def updateData(self, sourceitem):
        QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
        source = sourceitem.row()
        self.setHeader()
        if source in self.manager.inputs:#inputhistory:
            dlist = self.inputhistory[self.manager.inputs[source]]
            for row, data in enumerate(dlist):
                self.setRowCount(row + 1)
                for col, head in enumerate(INPUT_HEADER):
                    if getattr(data, head):
                        if head == "browser":
                            if getattr(data, head) == "Firefox":
                                item = QTableWidgetItem(QIcon(QPixmap(":firefox")), "FireFox")
                            else:
                                item = QTableWidgetItem(QIcon(QPixmap(":internet_explorer")),"IE")
                        else:
                            item = QTableWidgetItem(getattr(data, head))
                    else:
                        item = QTableWidgetItem("")
                    item.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
                    self.setItem(row, col, item)
        QApplication.restoreOverrideCursor()


class SourceList(QTableWidget):
    def __init__(self, manager):
        QTableWidget.__init__(self)
        self.manager = manager
        self.setHeader()

    def setHeader(self):
        self.setColumnCount(1)
        self.setRowCount(0)
        self.horizontalHeader().setStretchLastSection(True)
        self.setSortingEnabled(True)
        self.setHorizontalHeaderLabels(["Source"])
        self.setAlternatingRowColors(True)
#        self.setSelectionMode(QAbstractItemView.NoSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.verticalHeader().hide()

    def updateSources(self, sources):
        self.setHeader()
        for count, source in enumerate(sources):
            self.setRowCount(count + 1)
            item = QTableWidgetItem(source.absolute())
            item.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled|Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            self.manager.inputs[count] = source
            self.setItem(count, 0, item)

    def selected(self):
        row = 0
        res = []
        while row < self.rowCount():
            i = self.item(row, 0)
            if i.checkState() == Qt.Checked:
                res.append(self.manager.inputs[row])
            row += 1
        return res

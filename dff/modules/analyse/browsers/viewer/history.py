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

from ..history import History, HISTORY_HEADER 

class HistoryWidget(QWidget):
    def __init__(self, history):
        QWidget.__init__(self)
        self.history = history
        self.initShape()

    def initShape(self):
        self.layout = QHBoxLayout()
        self.splitter = QSplitter()
        self.domains = DomainList()
        self.domains.updateDomains(self.history.keys())
        self.records = RecordList(self)
        self.domains.connect(self.domains, 
                             SIGNAL('itemClicked(QTableWidgetItem *)'),
                             self.records.updateData)
        self.splitter.addWidget(self.domains)
        self.splitter.addWidget(self.records)
        self.layout.addWidget(self.splitter)
        self.setLayout(self.layout)

class RecordList(QTableWidget):
    def __init__(self, hmanager):
        QTableWidget.__init__(self)
        self.history = hmanager.history
        self.setHeader()

    def setHeader(self):
        self.setColumnCount(len(HISTORY_HEADER))
        self.setRowCount(0)
        self.horizontalHeader().setStretchLastSection(True)
        self.setSortingEnabled(True)
        self.setHorizontalHeaderLabels(HISTORY_HEADER)
        self.setAlternatingRowColors(True)
#        self.set
#        self.setSelectionMode(QAbstractItemView.NoSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.verticalHeader().hide()

    def updateData(self, domainitem):
        QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
        domain = unicode(domainitem.text())
        self.setHeader()
        if unicode(domain) in self.history:
            dlist = self.history[domain]
            for row, data in enumerate(dlist):
                self.setRowCount(row + 1)
                for col, head in enumerate(HISTORY_HEADER):
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


class DomainList(QTableWidget):
    def __init__(self):
        QTableWidget.__init__(self)
        self.setHeader()

    def setHeader(self):
        self.setColumnCount(1)
        self.setRowCount(0)
        self.horizontalHeader().setStretchLastSection(True)
        self.setSortingEnabled(True)
        self.setHorizontalHeaderLabels(["Domains"])
        self.setAlternatingRowColors(True)
#        self.setSelectionMode(QAbstractItemView.NoSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.verticalHeader().hide()

    def updateDomains(self, domains):
        self.setHeader()
        for count, domain in enumerate(domains):
            self.setRowCount(count + 1)
            item = QTableWidgetItem(domain)
            item.setCheckState(Qt.Unchecked)
            item.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled|Qt.ItemIsUserCheckable)
            self.setItem(count, 0, item)

    def selected(self):
        row = 0
        res = []
        while row < self.rowCount():
            i = self.item(row, 0)
            if i.checkState() == Qt.Checked:
                res.append(i.text())
            row += 1
        return res

    

        
        
  

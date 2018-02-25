# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
# 
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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 
import struct
import binascii

from PyQt4.QtCore import QString, Qt, SIGNAL
from PyQt4.QtGui import QWidget, QGroupBox, QVBoxLayout, QSpinBox, QGridLayout, QTreeWidget, QTreeWidgetItem, QApplication

from dff.api.exceptions.libexceptions import *

from decodeValues import *

class navigation(QWidget):
    def __init__(self,  parent):
        QWidget.__init__(self)
        self.heditor = parent
#        self.hexitem = parent.hexitem
        self.createShape()

    def createShape(self):
        self.vbox = QGridLayout()
        fill = QWidget()

#        self.createNavTree()
#        self.createNavTreeItems()
        self.createDecode()

        self.vbox.addWidget(fill)
        self.setLayout(self.vbox)

    def createNavTree(self):
        self.navgroup = QGroupBox("Nav Informations")

        self.layout = QVBoxLayout()

        self.navtree = QTreeWidget()
        self.navtree.setColumnCount(2)
        
        headerLabels = [QApplication.translate("navigation", "Current", None, QApplication.UnicodeUTF8),
                       QApplication.translate("navigation", "Value", None, QApplication.UnicodeUTF8)]
        
        self.navtree.setHeaderLabels(headerLabels)
        self.navtree.setAlternatingRowColors(True)

        self.layout.addWidget(self.navtree)
        self.navgroup.setLayout(self.layout)

    def createNavTreeItems(self):
        self.fs = QTreeWidgetItem(self.navtree)
        self.fs.setText(0, "File size")
        f = "%.2d" % self.heditor.filesize
        self.fs.setText(1, f)

        self.curoff = QTreeWidgetItem(self.navtree)
        self.curoff.setText(0, "Curr. offset")
        self.curpage = QTreeWidgetItem(self.navtree)
        self.curpage.setText(0, "Curr. page")
        self.curblock = QTreeWidgetItem(self.navtree)
        self.curblock.setText(0, "Curr. block")

        self.cursoroff = QTreeWidgetItem(self.navtree)
        self.cursoroff.setText(0, "Cursor")
        self.vbox.addWidget(self.navgroup)

    def createDecode(self):
        self.vdecode = QVBoxLayout()
        self.decode = decodeValues(self.heditor)
        self.vbox.addWidget(self.decode)

    def updateFs(self):
        if self.heditor.decimalview:
            f = "%.2d" % self.heditor.filesize
        else:
            f = "%.2x" % self.heditor.filesize
        self.fs.setText(1, f)

    def update(self):
        if self.heditor.decimalview:
            off = "%.2d" % self.heditor.currentOffset
            page = "%.2d" % self.heditor.currentPage
            block = "%.2d" % self.heditor.currentBlock
            select = "%.2d" % self.heditor.currentSelection
        else:
            off = "%.2x" % self.heditor.currentOffset
            page = "%.2x" % self.heditor.currentPage
            block = "%.2x" % self.heditor.currentBlock
            select = "%.2x" % self.heditor.currentSelection
        self.curoff.setText(1, off)
        self.curpage.setText(1, page)
        self.curblock.setText(1, block)
        self.cursoroff.setText(1, select)




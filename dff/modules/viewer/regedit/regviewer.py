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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 
import pyregfi

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from dff.api.vfs import *
from dff.api.vfs.libvfs import *
from dff.api.exceptions.libexceptions import *

from dff.modules.winreg.pathmanager import *
from dff.modules.winreg.regtype import regtype

class regviewer(QVBoxLayout):
    def __init__(self, mainw, mountpoints):
        super(regviewer,  self).__init__(mainw)
        self.mainw = mainw
        self.mountpoints = mountpoints

        for mp in self.mountpoints:
            rm = rootManager(mp.value())
            self.hives = rm.getHives()

        self.init()

    def init(self):
        self.initViewShape()

    def initViewShape(self):
        self.splitter = QSplitter()
        self.tree = hiveTree(self, self.hives)
        self.table = tableView(self)
        self.splitter.addWidget(self.tree)
        self.splitter.addWidget(self.table)
        self.addWidget(self.splitter)

class hiveTree(QTreeWidget):
    def __init__(self, parent, hives):
        super(hiveTree,  self).__init__()
        self.regv = parent
        self.hivesnodes = hives
        self.hives = []
        self.openHives()
        self.createTree()

        self.connect(self, SIGNAL("itemClicked(QTreeWidgetItem *, int)"), self.clicked)

    def openHives(self):
        for hivenode in self.hivesnodes:
#            print "fsobj name : ", hivenode.value().fsobj().name
            self.hives.append(pyregfi.Hive(hivenode.open()))

    def createTree(self):
        for hive in self.hives:
            self.registree(hive.root, QString(""), hive)

    def registree(self, currentkey, path, hive, parentitem=None):
        if len(currentkey.subkeys) > 0:
            i = self.createTreeItem(parentitem, hive, currentkey, path)
            for key in currentkey.subkeys:
                v = QVariant(getattr(key, "name"))
                
                self.registree(key, QString(path) + "/" + v.toString(), hive, i)
        else:
            self.createTreeItem(parentitem, hive, currentkey, path)
 
    def createTreeItem(self, parent, hive, currentkey, path):
        if parent:
            item = treeItem(parent, path, hive)
        else:
            item = treeItem(self, path, hive)
        v = QVariant(getattr(currentkey, "name"))
        item.setText(0, v.toString())
        item.setIcon(0, QIcon(":password.png"))
        return item

    def clicked(self, item, column):
        self.regv.table.refreshValues(item.hive, str(item.path.toAscii()))
    

class treeItem(QTreeWidgetItem):
    def __init__(self, parent, path, hive):
        super(treeItem,  self).__init__(parent)
        self.path = path
        self.hive = hive

class tableView(QTableWidget):
    def __init__(self, parent):
        super(tableView,  self).__init__()
        self.parent = parent
        self.setHeaders()
        
    def setHeaders(self):
        self.setColumnCount(3)
        self.setHorizontalHeaderItem(0, QTableWidgetItem(QString("Name")))
        self.setHorizontalHeaderItem(1, QTableWidgetItem(QString("Type")))
        self.setHorizontalHeaderItem(2, QTableWidgetItem(QString("Data")))
        self.horizontalHeader().setStretchLastSection(True)
        self.setAlternatingRowColors(True)
        self.verticalHeader().hide()

    def refreshValues(self, hive, path):
        self.clear()
        self.setRowCount(0)
        self.setHeaders()
        w = pathManager(hive, path)
        values = w.getValues()
        if values:
            i = 1
            for value in values:
                self.setRowCount(i)
                if value.name:
                    name = QTableWidgetItem(QString(value.name.encode('utf-8', 'replace'))) 
                else:
                    name = QTableWidgetItem(QString("Default")) 
                vtype = QTableWidgetItem(QString(regtype[getattr(value, "type")])) 
                d = QVariant(value.fetch_data())
                data = QTableWidgetItem(QString(d.toString()))

                self.setItem(i - 1, 0, name)
                self.setItem(i - 1, 1, vtype)
                self.setItem(i- 1, 2, data)
                i += 1
        

            


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
import os, sys, re
import os.path as osp

from PyQt4.QtGui import QTreeView, QDirModel
from PyQt4.QtCore import Qt, SIGNAL, QString, QStringList, QDir

class Explorer(QTreeView):
    def __init__(self, parent=None, path=None):
        QTreeView.__init__(self, parent)
        self.ide = parent
        self.path = path

        self.model = explorerModel()

        self.setModel(self.model)
        self.setColumnHidden(3, True)
        self.setColumnHidden(2, True)

        self.setAnimated(False)
        self.setSortingEnabled(True)
        self.sortByColumn(0, Qt.AscendingOrder)
        
    def mouseDoubleClickEvent(self, event):
        index = self.currentIndex()
        if index:
            localpath = osp.normpath(unicode(self.model.filePath(index)))
            if osp.isdir(localpath):
                self.setExpanded(index, True)
            else:
                self.ide.open(localpath)

class explorerModel(QDirModel):
    def __init__(self, parent=None):
        QDirModel.__init__(self, parent)
        self.filter = QDir.AllDirs | QDir.Files | QDir.Drives | QDir.NoDotAndDotDot
        self.sortflags = QDir.Name | QDir.DirsFirst | \
            QDir.IgnoreCase | QDir.LocaleAware

        self.nameFilter = ["*.py", "*.pyw"]

        self.setNameFilters(self.nameFilter)
        self.setFilter(self.filter)
        self.setSorting(self.sortflags)

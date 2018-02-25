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
import os

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import QTreeView, QAbstractItemView

class RegTreeView(QTreeView):
  def __init__(self, parent = None):
    QTreeView.__init__(self)
    self.setUniformRowHeights(True)
    self.setItemsExpandable(True)
    self.setExpandsOnDoubleClick(True)
    self.connect(self, SIGNAL("expanded(QModelIndex)"), self.indexExpanded)

  def indexExpanded(self, index):
      if index.isValid():
        self.model().refreshTree(index)

  def mousePressEvent(self, e):
    try:
      index = self.indexAt(e.pos())
      if index.isValid():
        self.model().selectKey(index)
    except:
      pass
    QTreeView.mousePressEvent(self, e)


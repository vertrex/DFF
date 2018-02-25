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
#  Romain Bertholon <rbe@digital-forensic.org>
# 
from PyQt4 import QtCore, QtGui

from PyQt4.QtGui import QWidget, QDateTimeEdit, QLineEdit, QHBoxLayout, QLabel, QPushButton, QMessageBox, QListWidget, QTableWidget, QTableWidgetItem, QAbstractItemView, QIcon, QInputDialog, QTableView
from PyQt4.QtCore import QVariant, SIGNAL, QThread, Qt, QFile, QIODevice, QStringList, QRect, SLOT, QEvent, QString

from dff.api.vfs.vfs import vfs
from dff.api.vfs.libvfs import VFS, Node, VLink, VecNode
from dff.api.filters.libfilters import Filter
from dff.api.types.libtypes import Variant, typeId
from dff.api.events.libevents import EventHandler, event

class SearchThread(QThread, EventHandler):
  def __init__(self, parent=None):
    EventHandler.__init__(self)
    QThread.__init__(self)
    self.__parent = parent
    self.nodes = []
    self.filters = Filter("search")
    self.filters.connection(self)
    self.model = None
    self.listmode = False

  def setListContext(self, query, nodelist, targetmodel):
    self.listmode = True
    self.nodes = VecNode()
    for node in nodelist:
      self.nodes.append(node)
    self.model = targetmodel
    try:
      self.filters.compile(query)
      return True
    except:
      box = QMessageBox(QMessageBox.Critical, self.tr("Error"), self.tr("Error compiling query"), \
                          QMessageBox.NoButton, self.__parent)
      box.setDetailedText(QString.fromUtf8(query))
      box.exec_()
      return False

  def setContext(self, query, rootnode, targetmodel):
    self.listmode = False
    self.rootnode = rootnode
    self.model = targetmodel
    try:
      self.filters.compile(query)
      return True
    except Exception as e:
      print e
      box = QMessageBox(QMessageBox.Critical, self.tr("Error"), self.tr("Error compiling query"), \
                          QMessageBox.NoButton, self.__parent)
      box.setDetailedText(QString.fromUtf8(query))
      box.exec_()
      return False

  def Event(self, e):
    if e != None:
      if e.value != None:
        if e.type == Filter.EndOfProcessing:
          self.emit(SIGNAL("finished"))
        if e.type == Filter.TotalNodesToProcess:
          self.total = e.value.value()
        if e.type == Filter.ProcessedNodes:
          self.processed += 1
        if e.type == Filter.NodeMatched:
          self.match += 1
          val = e.value.value()
          self.model.emit(SIGNAL("appendList"), val)
          self.emit(SIGNAL("match"))
        pc = self.processed * 100 / self.total
        try:
          if pc > self.percent:
            self.percent = pc
            self.emit(SIGNAL("count"), self.percent)
        except:
          self.percent = 0

  def run(self):
    self.emit(SIGNAL("started"))
    self.match = 0
    self.processed = 0
    self.total = 0
    self.percent = 0
    try:
      if not self.listmode:
        self.filters.process(self.rootnode, True)
      else:
        self.filters.process(self.nodes)
    except:
      pass

  def stopSearch(self):
    e = event()
    e.thisown = False
    e.type = Filter.StopProcessing
    self.filters.Event(e)


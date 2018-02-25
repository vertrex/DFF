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
#  Jeremy MOUNIER <jmo@digital-forensic.org>

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

from dff.api.vfs.libvfs import VLink

DEFAULT_SIZE = 16

class NodeListView(QListView):
  def __init__(self, widget):
     super(NodeListView, self).__init__(widget)
     self.width = DEFAULT_SIZE
     self.height = DEFAULT_SIZE
     self.wpad = 25
     self.hpad = 30
     self.factor = 1
     self.tablewidget = widget
     self.delegate = CheckStateListDelegate(self)
     self.configure()

  def configure(self):
     self.setItemDelegate(self.delegate)
     self.w = self.width + (self.factor * 32)
     self.h = self.height + (self.factor * 32)
     self.setIconSize(QSize(self.w, self.h))
     self.setGridSize(QSize(self.w + self.wpad, self.h + self.hpad))
     self.setLayoutMode(QListView.Batched)
     self.setViewMode(QListView.IconMode)
     self.setUniformItemSizes(True)
     self.setFlow(QListView.LeftToRight)
     self.setSelectionMode(QAbstractItemView.NoSelection)
     self.setBatchSize(50)
     self.setWordWrap(True)
     self.setTextElideMode(Qt.ElideRight)
     self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
     self.setWrapping(True)

  def resizeEvent(self, event):
    self.refreshVisible()

  def refreshVisible(self):
    try:
      self.rows = (self.viewport().height() / (self.h + self.hpad))
      self.cols = self.viewport().width() / (self.w + self.wpad)
      visible = ((self.rows  + 1) * self.cols) - 1
      self.model().setVisibleRows(visible)
    except:
      return

  def viewOptions(self):
    option = QStyleOptionViewItem()
    option.decorationPosition = QStyleOptionViewItem.Top
    option.decorationAlignment = Qt.AlignCenter
    option.decorationSize = QSize(self.w,self.h)
    option.displayAlignment = Qt.AlignBottom
    option.state = QStyle.State_Enabled
    return option

  def select(self, row):
    self.update(self.model().index(self.model().activeSelection(), 0))
    self.model().select(row)
    self.update(self.model().index(self.model().activeSelection(), 0))
    index = self.model().index(row, 0)
    node = self.model().getNode(self.model().currentRow() + row)
    if node:
      self.tablewidget.emit(SIGNAL("nodePressed"), node)
      
  def mousePressEvent(self, event):
    index = self.indexAt(event.pos())
    self.select(index.row())

  def mouseDoubleClickEvent(self, event):
    index = self.indexAt(event.pos())
    self.select(index.row())
    node = self.model().getNode(self.model().currentRow() + index.row())
    if isinstance(node, VLink):
      node = node.linkNode()
    if node.isDir() or node.hasChildren():
      self.emit(SIGNAL("enterDirectory"), node)
    else:
      self.emit(SIGNAL("nodeListDoubleClicked"), node)

  def wheelEvent(self, event):
    scroll = self.tablewidget.scrollbar
    if event.delta() > 0:
      v = self.model().seek(-self.cols, 1)
    else:
      v = self.model().seek(self.cols, 1)

  def keyPressEvent(self, event):
    node = self.model().currentNode()
    if node != None:
      if isinstance(node, VLink):
        node = node.linkNode()
    if event.key() == Qt.Key_Backspace:
      node = self.model().currentRoot()
      if node:
        self.emit(SIGNAL("enterDirectory"), node.parent())
    if event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
      if node != None:
        if node.isDir() or node.hasChildren():
          self.emit(SIGNAL("enterDirectory"), node)
        else:
          self.emit(SIGNAL("nodeListDoubleClicked"), node)              
    if event.key() == Qt.Key_Space:
      if node != None:
        if not self.model().selection.isChecked(node):
          self.model().selection.add(node)
        else:
          self.model().selection.rm(node)
    if event.matches(QKeySequence.MoveToNextLine):
      if self.model().activeSelection() + self.cols >= self.model().visibleRows() - self.cols:
        self.model().seek(self.cols, 1)
      self.select(self.model().activeSelection() + self.cols)
    elif event.matches(QKeySequence.MoveToPreviousLine):
      if self.model().activeSelection() - self.cols <= 0:
        self.model().seek(-self.cols, 1)
      self.select(self.model().activeSelection() - self.cols)
    elif event.matches(QKeySequence.MoveToPreviousPage):
      self.model().seek(-(self.model().visibleRows() - 1), 1)
      self.select(0)
    elif event.matches(QKeySequence.MoveToNextPage):
      self.model().seek(self.model().visibleRows() - 1, 1)
      self.select(0)
    elif event.matches(QKeySequence.MoveToNextChar):
      self.select(self.model().activeSelection() + 1)
    elif event.matches(QKeySequence.MoveToPreviousChar):
      self.select(self.model().activeSelection() - 1)

class TimeLineNodeListView(NodeListView):
  def __init__(self, widget):
    NodeListView.__init__(self, widget)

class CheckStateListDelegate(QStyledItemDelegate):
  def __init__(self, parent):
    QStyledItemDelegate.__init__(self, parent) 
    self.view = parent


  def sizeHint(self, option, index):
    w = (self.view.width + (self.view.factor * 32)) + self.view.wpad
    h = (self.view.height + (self.view.factor * 32)) +  self.view.hpad
    return QSize(w, h)

  def editorEvent(self, event, model, option, index):
    if index.isValid():
      select = False
      if event.type() == QEvent.MouseButtonRelease:
        model.select(index.row())
        self.view.emit(SIGNAL("nodeListClicked"), event.button())
        select = True
      # Detect checkbox click in order to avoid column style detection
      element = self.view.style().subElementRect(QStyle.SE_CheckBoxIndicator, option)
      if select and element.contains(event.pos()):
        node = model.currentNode()
        if node != None:
          if not model.selection.isChecked(node):
            model.selection.add(node)
          else:
            model.selection.rm(node)
      return QStyledItemDelegate.editorEvent(self, event, model, option, index)
    else:
      return False

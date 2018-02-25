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

from dff.api.vfs.libvfs import VFS, VLink

DEFAULT_SIZE = 20

class NodeTableView(QTableView):
    def __init__(self, tablewidget):
        QTableView.__init__(self)
        self.tablewidget = tablewidget
        self.headerorder = {}
        self.delegate = CheckStateDelegate(self)
        self.setItemDelegate(self.delegate)
        self.factor = 1
        self.configure()

    def configure(self):
        self.verticalHeader().setDefaultSectionSize(DEFAULT_SIZE * self.factor)
        self.setIconSize(QSize(DEFAULT_SIZE * self.factor, DEFAULT_SIZE * self.factor))
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setShowGrid(False)
        self.setAutoScroll(False)
        self.setSelectionMode(QAbstractItemView.NoSelection)
        self.configureHeaders()

    def configureHeaders(self):
        self.horizontalHeader().setStretchLastSection(True)
	self.horizontalHeader().setMovable(True)
        self.connect(self.horizontalHeader(), SIGNAL("sectionClicked(int)"), self.headerClicked)
        self.verticalHeader().hide()

    def refreshVisible(self):
        height = self.factor * DEFAULT_SIZE
        if height < self.rowHeight(0):
            heigth = self.rowHeight(0)
        try:
            visible = self.viewport().height() / height
            if visible > 0:
                self.model().setVisibleRows(visible)
        except:
            return

    def resizeEvent(self, event):
      self.refreshVisible()

    def wheelEvent(self, event):
        currentrow = self.model().currentRow()
        if self.model().size() <= self.model().visibleRows():
            return
        if event.delta() < 0:
            if currentrow + 3 >= (self.model().size() - self.model().visibleRows()):
                v = self.model().seek(self.model().size())
                return
        if event.delta() > 0:
            v = self.model().seek(-3, 1)
            return
        else:
            v = self.model().seek(3, 1)
            return


    def mouseDoubleClickEvent(self, event):
        index = self.indexAt(event.pos())
        self.model().select(index.row())
        node = self.model().getNode(self.model().currentRow() + index.row())
        if node != None:
        # This is a directory
            if isinstance(node, VLink):
              node = node.linkNode()
            if node.isDir() or node.hasChildren():
                self.emit(SIGNAL("enterDirectory"), node)
            else:
                self.emit(SIGNAL("nodeListDoubleClicked"), node)


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
            if self.model().activeSelection() + 1 >= self.model().visibleRows():
                self.model().seek(1, 1)
                self.model().select(self.model().visibleRows() - 1)
            else:
                self.model().select(self.model().activeSelection() + 1)
        elif event.matches(QKeySequence.MoveToPreviousLine):
            if self.model().activeSelection() - 1 <= 0:
                self.model().seek(-1, 1)
                self.model().select(0)
            else:
                self.model().select(self.model().activeSelection() - 1)
        elif event.matches(QKeySequence.MoveToPreviousPage):
            self.model().seek(-(self.model().visibleRows() - 1), 1)
            self.model().select(0)
        elif event.matches(QKeySequence.MoveToNextPage):
            self.model().seek(self.model().visibleRows() - 1, 1)
            self.model().select(0)


    def headerClicked(self, col):
      self.horizontalHeader().setSortIndicatorShown(True)
      if col in self.headerorder:
        if self.headerorder[col] == Qt.DescendingOrder:
          order = Qt.AscendingOrder
        else:
          order = Qt.DescendingOrder
      else:
        order = Qt.DescendingOrder
      self.headerorder[col] = order
      self.model().sort(col, order)

class TimeLineNodeTableView(NodeTableView):
  def __init__(self, tableWidget):
    NodeTableView.__init__(self, tableWidget)

class HeaderView(QHeaderView):
    def __init__(self, view):
        QHeaderView.__init__(self, Qt.Horizontal)
        self.isOn = False
        self.view = view
        self.setStretchLastSection(True)
        self.setClickable(True)

    def paintSection(self, painter, rect, logicalIndex):
        painter.save()
        QHeaderView.paintSection(self, painter, rect, logicalIndex)
        painter.restore()
        option = QStyleOptionButton()
        if logicalIndex == 0:
            option.rect = QRect(3,2,20,20)
            model = self.view.model()
            if (self.isOn):
                option.state = QStyle.State_On|QStyle.State_Enabled
            else:
                option.state = QStyle.State_Off|QStyle.State_Enabled
        self.setSortIndicator(logicalIndex, True)
        self.style().drawPrimitive(QStyle.PE_IndicatorCheckBox, option, painter)
        
    def mousePressEvent(self, event):
        option = QStyleOptionButton()
        option.rect = QRect(3,2,20,20)
        element = self.style().subElementRect(QStyle.SE_CheckBoxIndicator, option)
        if element.contains(event.pos()):
            if self.isOn:
                self.isOn = False
                self.emit(SIGNAL("headerSelectionClicked"), False)
            else:
                self.emit(SIGNAL("headerSelectionClicked"), True)
                self.isOn = True
            self.update()
            self.headerDataChanged(Qt.Horizontal, 0, 0)
        else:
            index = self.logicalIndexAt(event.pos())
            if self.cursor().shape() != Qt.SplitHCursor:
                self.view.headerClicked(index)
        QHeaderView.mousePressEvent(self, event)


class CheckStateDelegate(QStyledItemDelegate):
  def __init__(self, parent):
    QStyledItemDelegate.__init__(self, parent) 
    self.view = parent
    self.tagSpacement = 10	
    self.tagBorderSpacement = 10

  def paint(self, painter, options, index):
      QStyledItemDelegate.paint(self, painter, options, index)
      if index.isValid():
	  try:
	    attrname = self.view.model().availableAttributes()[index.column()]
	  except KeyError:
	    attrname == None
          if attrname == "tags": 
              absrow = self.view.model().currentRow() + index.row()
              node = self.view.model().getNode(absrow)
              tags = node.tags()
              if len(tags) and node != None:
                  painter.save()
                  self.initStyleOption(options, index)
                  painter.setClipRect(options.rect)
                  options.rect.setX(self.tagBorderSpacement + options.rect.x())
                  for tag in tags:
                      textRect = painter.boundingRect(options.rect, Qt.AlignLeft | Qt.AlignVCenter, tag.name())
                      textRect.setWidth(textRect.width() + self.tagBorderSpacement) #space inside drawing rect for cented text
                      
                      oldBrush = painter.brush()
                      color = tag.color()
                      
                      oldPen = painter.pen()
                      painter.setPen(QPen(QColor(color.r, color.g, color.b)))
                      painter.setBrush(QColor(color.r, color.g, color.b))
                      painter.drawRect(textRect)
                      painter.setPen(oldPen)
                      
                      textCenter = options.rect
                      #space to center text
                      textCenter.setX(textCenter.x() + (self.tagBorderSpacement / 2))
                                      
                      painter.drawText(textCenter, Qt.AlignLeft | Qt.AlignVCenter, QString.fromUtf8(tag.name()))
                      #space between tag
                      options.rect.setX(options.rect.x() + textRect.width() + self.tagSpacement) 
                      
                  painter.restore()
 
  def editorEvent(self, event, model, option, index):
      if event.type() == QEvent.MouseButtonPress and index.isValid():
          model.select(index.row())
          self.view.emit(SIGNAL("nodeListClicked"), event.button())
          # Detect checkbox click in order to avoid column style detection
          element = self.view.style().subElementRect(QStyle.SE_CheckBoxIndicator, option)
          if element.contains(event.pos()) and index.column() == 0:
              node = model.currentNode()
              if node != None:
                  if not model.selection.isChecked(node):
                      model.selection.add(node)
                  else:
                      model.selection.rm(node)
                  self.view.refreshVisible()
          return QStyledItemDelegate.editorEvent(self, event, model, option, index)
      else:
          return False



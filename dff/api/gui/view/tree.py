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
#  Solal Jacob <sja@digital-forensic.org>
#  Romain Bertholon <rbe@digital-forensic.org>
# 
import os

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

from dff.api.vfs.libvfs import VFS

from dff.ui.gui.utils.menu import TreeMenu

class NodeTreeView(QTreeView):
  """
  This view is used to display the node tree view (in the left part of the Gui).

  Only directories and nodes having children does appear in this tree, files are not
  displayed.

  """
  def __init__(self, parent = None, coord = False):
    """
    Constructor
    """
    QTreeView.__init__(self)
    self.VFS = VFS.Get()
    self.setSelectionMode(QAbstractItemView.NoSelection)
    self.setState(QAbstractItemView.NoState)
    self.setUniformRowHeights(True)
    self.setSortingEnabled(False)
    self.coord = coord
    self.delegate = CheckDelegate(self)
    self.setItemDelegate(self.delegate)
    self.connect(self, SIGNAL("expanded(QModelIndex)"), self.indexExpanded)

  def indexExpanded(self, index):
    node = self.model().getNodeFromIndex(index)
    if node != None:
      self.model().refreshModel(node)
      self.resizeColumnToContents(0)

  def keyPressEvent(self, e):
    row = self.currentIndex().row()
    if e.matches(QKeySequence.MoveToNextLine):
      index = self.moveCursor(QAbstractItemView.MoveDown, Qt.NoModifier)
    elif e.matches(QKeySequence.MoveToPreviousLine):
      index = self.moveCursor(QAbstractItemView.MoveUp, Qt.NoModifier)
    elif e.matches(QKeySequence.MoveToNextChar):
      self.expand(self.currentIndex())
      return
    elif e.matches(QKeySequence.MoveToPreviousChar):
      self.collapse(self.currentIndex())
      return
    else:
      index = self.currentIndex()
    if index.isValid():
      self.model().emit(SIGNAL("layoutAboutToBeChanged"))
      self.model().setCurrentIndex(self.currentIndex(), index)
      self.setCurrentIndex(index)
      self.model().emit(SIGNAL("layoutChanged"))
      node = self.model().getNodeFromIndex(index)
      if (node != None):
        if e.key() == Qt.Key_Space:
          if not self.model().selection.isChecked(node):
            self.model().selection.add(node)
          else:
            self.model().selection.rm(node)
        rec = index.data(Qt.UserRole + 3).toBool()
        self.emit(SIGNAL("nodeTreeClicked"), node, 0, rec)

  def mouseMoveEvent(self, e):
    pass

  def mousePressEvent(self, e):
    try:
      index = self.indexAt(e.pos())
      if index.isValid():
        if e.button() == Qt.RightButton:
          node = self.model().getNodeFromIndex(index)
          if node.absolute().find('/Bookmarks/') == 0:
            menu = TreeMenu(self, node)
            menu.popup(QCursor.pos())
        self.model().emit(SIGNAL("layoutAboutToBeChanged"))
        self.model().setCurrentIndex(self.currentIndex(), index)
        self.setCurrentIndex(index)
        self.model().emit(SIGNAL("layoutChanged"))
      if self.coord:
        self.resizeColumnToContents(0)
    except:
      pass
    QTreeView.mousePressEvent(self, e)
 
  def mouseDoubleClickEvent(self, e):
    """
    \reimp

    When users double-click on a node in the tree view, it expands the node.

    A nodeTreeClicked signal is emitted.

    \param e the event
    """
    try:
      index = self.indexAt(e.pos())
      if index.isValid():
        self.model().emit(SIGNAL("layoutAboutToBeChanged"))
        self.model().setCurrentIndex(self.currentIndex(), index)
        self.setCurrentIndex(index)
        self.model().emit(SIGNAL("layoutChanged"))
    except:
      return
    QTreeView.mouseDoubleClickEvent(self, e)

  def expandToNode(self, node):
    QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
    item = self.model().getItemFromNode(node)
    if item != None:
      index = item.index()
      if index.isValid():
        n = self.model().getNodeFromIndex(index)
        self.model().setCurrentIndex(self.currentIndex(), index)
        self.setCurrentIndex(index)
        self.setExpanded(index, True)
        self.scrollTo(index)
    else:
      self.model().refreshModel(node)
    self.resizeColumnToContents(0)
    QApplication.restoreOverrideCursor()

  def indexRowSizeHint(self, index):
    return 2

  def loadStylesheet(self):
    path = os.path.abspath(os.path.join(os.getcwd(), "ui", "gui", "resources", "stylesheets", "treeview.qss"))
    f = QFile(path)
    f.open(QFile.ReadOnly)
    styleSheet = QLatin1String(f.readAll())
    self.setStyleSheet(styleSheet)
    f.close()
    
class CheckDelegate(QStyledItemDelegate):
  def __init__(self, parent):
    QStyledItemDelegate.__init__(self, parent) 
    self.view = parent

  def paint(self, painter, options, index):
    if index.isValid():
      if index.column() == 0:
        painter.save()
        data = index.data(Qt.UserRole + 3)
        if data.toBool():
          icon = QPixmap(":rectree_on").scaled(QSize(16, 16), Qt.KeepAspectRatio)
        else:
          icon = QPixmap(":rectree_off").scaled(QSize(16, 16), Qt.KeepAspectRatio)
        zx = options.rect.x()
        zy = options.rect.y()
        painter.drawPixmap(QRect(zx, zy + 2, icon.width(), icon.height()), icon)
        painter.restore()
    options.rect.setX(options.rect.x() + icon.width())
    QStyledItemDelegate.paint(self, painter, options, index)

  def editorEvent(self, event, model, option, index):
    e = event
    if index.isValid():
      var = model.data(index, Qt.UserRole + 1)
      node = self.view.VFS.getNodeById(var.toULongLong()[0])
      if node == None:
        pass
      rec = index.data(Qt.UserRole + 3).toBool()
      pos = event.pos()
      newposx = event.pos().x() - 16
      if event.type() not in [QEvent.MouseMove, QEvent.MouseButtonRelease] or not (option.state & QStyle.State_Enabled):
        if (newposx <= option.rect.x()) and (newposx >= option.rect.x() - 16):
          # We are on recursive icon
          item = model.itemFromIndex(index)
          if rec:
            item.setData(False, Qt.UserRole + 3)
            rec = False
          else:
            item.setData(True, Qt.UserRole + 3)
            rec = True
        # XXX CheckBox positions
        elif (newposx >= option.rect.x() + 6) and (newposx <= option.rect.x() + 19):
          state = index.data(Qt.CheckStateRole).toBool()
          if not state:
            model.selection.add(node)
          else:
            model.selection.rm(node)

        pos.setX(newposx)
        e = QMouseEvent(event.type(), pos, event.button(), event.buttons(), event.modifiers())
        if (node != None):
          self.view.emit(SIGNAL("nodeTreeClicked"), node, event.button(), rec)
      return QStyledItemDelegate.editorEvent(self, e, model, option, index)
    else:
      return False

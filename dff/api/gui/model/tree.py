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
#  Romain Bertholon <rbe@digital-forensic.org>
# 
import re
from Queue import *
import locale

from PyQt4.QtCore import SIGNAL, QAbstractItemModel, QModelIndex, QVariant, Qt, QDateTime, QSize, QThread, QMutex, QSemaphore, QString, Qt
from PyQt4.QtGui import QColor, QIcon, QImage, QImageReader, QPixmap, QPixmapCache, QStandardItemModel, QStandardItem, QStyledItemDelegate, QBrush, QPen, QPalette, QPainter
from PyQt4 import QtCore

from dff.api.types.libtypes import Variant
from dff.api.vfs.libvfs import VFS
from dff.api.events.libevents import EventHandler

class TreeModel(QStandardItemModel, EventHandler):
  def __init__(self, __parent = None, selection=None, root=None):
    QStandardItemModel.__init__(self, __parent)
    EventHandler.__init__(self)
    self.__parent = __parent
    self.VFS = VFS.Get()
    # init translation
    self.root_node = root
    self.__root_uids = []
    self.translation()
    self.itemmap = {}
    self.createRootItems()
    self.currentIndex = self.root_item
    self.ch = True
    self.displayCount = True
    self.selection = selection
    if self.selection != None:
      self.connect(self.selection, SIGNAL("selectionChanged"), self.updateSelected)
    self.VFS.connection(self)
    # keep track of index - node pointers
    self.connect(self, SIGNAL("refreshModel"), self.refreshModel)

  def updateSelected(self, count):
    self.emit(SIGNAL("layoutChanged()"))
    
  def enableDisplayCount(self):
    self.displayCount = True

  def disableDisplayCount(self):
    self.displayCount = False

  def createRootItems(self):
    # Add Root children items (bookmarks, logical etc.)
    self.root_item = self.invisibleRootItem()
    if not self.root_node:
      self.root_node = self.VFS.GetNode("/")

    self.vfsroot = self.VFS.GetNode("/")
    tmp = self.root_node.children()
    item_list = []
    for i in tmp:
      node_item = QStandardItem(i.name())
      node_item.setData(QVariant(i.uid()), Qt.UserRole + 1)
      self.__root_uids.append(i.uid())
      node_item.setData(QVariant(False), Qt.UserRole + 2)
      item_list.append(node_item)
      self.itemmap[i.uid()] = node_item
    if len(item_list):
      self.root_item.appendRows(item_list)

  def headerData(self, section, orientation, role=Qt.DisplayRole):
    """
    \reimp

    The only column is the `name` column. 

    \return QVariant("Name") if the role is Qt.DisplatRole, an invalid QVariant otherwise.
    """
    if role != Qt.DisplayRole:
      return QVariant()
    else:
      return QVariant(self.nameTr)

  def data(self, index, role):
    """
    \reimp

    Nodes' pointers are encapsulated in QStandardItem (role : Qt.UserRole + 1). Most
    of the data can only be retrieved only if the node is retrieved:

    * The node name
    * The node icon
    * ...

    To do so, the TreeModel.data() method calls the QStandardItemModel.data() method by passing
    the `index` parameter and `Qt.UserRole + 1` or `Qt.UserRole + 2` to it. In the second case, it
    retrieves a boolean used to know if the node is already expended and returns directly.

    \param index the index of the data we want to get
    \param role the role of the data we want to retrieve

    \return a QVariant containing the data, or an invalid QVariant if the data could not be retrieved.
    """
    if not index.isValid():
      return QVariant()
    # Qt.UserRole + 2 contain a boolean indicating if the node has already been expanded
    # in the tree.
    if role == Qt.UserRole + 3:
      return QStandardItemModel.data(self, index, role)
    if role == Qt.UserRole + 2:
      return QStandardItemModel.data(self, index, role)
    # call QStandardItemModel.data method with a Qt.UserRole + 1 to get the pointer on the node
    # (returns a invalid QVariant if the node or the data is None)
    data = QStandardItemModel.data(self, index, Qt.UserRole + 1)
    if not data.isValid():
      return data
    # getting the node or returning an invalid QVariant() if the node is not valid
    uid, valid = data.toULongLong()
    if not valid:
      return QVariant()
    node = self.VFS.getNodeById(uid)
    if node is None:
      return QVariant()
    # if role == UserRole + 1, it means that the node itself must be returned (the pointer
    # on the node, encapsulated in a QVariant()
    if role == (Qt.UserRole + 1):
      return data
    # in other cases, returns the requires data  : icon, color, etc. or an invalid QVariant()
    # if the role does not correpond to anything.
    if role == Qt.DisplayRole :
      display = QString.fromUtf8(node.name())
      if self.displayCount:
        display += QString("  (" + str(node.totalChildrenCount()) + ")")
      return QVariant(display)
    if role == Qt.DecorationRole:
      pixmap = QPixmap(node.icon())
      if node.hasChildren():
        try:
          pfsobj = node.children()[0].fsobj().this #XXX fsobj have uid now
        except AttributeError:
  	  pfsobj = None
        try:
          nfsobj = node.fsobj().this
        except AttributeError:
	  nfsobj = None
        if pfsobj != nfsobj:
          pixmap = pixmap.scaled(QSize(128, 128), Qt.KeepAspectRatio)
          painter = QPainter(pixmap)
          rootPixmap = QPixmap(":root")
          painter.drawPixmap(0, 0, rootPixmap)
          painter.end()
      return QVariant(QIcon(pixmap))
    if role == Qt.BackgroundRole:
      if index == self.currentIndex:
        palette = QPalette().color(QPalette.Highlight)
        return QVariant(QColor(palette))
    if role == Qt.ForegroundRole:
      if (index == self.currentIndex) and not node.isDeleted():
        palette = QPalette().color(QPalette.HighlightedText)
        return QVariant(QColor(palette))
      if node.isDeleted():
        return  QVariant(QColor(Qt.red))
    if self.ch == True:
      if role == Qt.CheckStateRole:
        if index.column() == 0:
          if node.uid() in self.selection.get():
            return Qt.Checked
          else:
            return Qt.Unchecked

    return QVariant()

  def setData(self, index, value, role):
    """
    \reimp

    Set the data which value is `value` at index `index` with role `role`.

    \return `True` if no error occured, `False` otherwise.
    """
    if self.ch == True:
      if role == Qt.CheckStateRole:
        ret =  QStandardItemModel.setData(self, index, value, role)
        if ret == False:
          return False
        data = QStandardItemModel.data(self, index, Qt.UserRole + 1)
        if not data.isValid():
          return False
        self.emit(SIGNAL("stateChanged"), index)
    return True

  def columnCount(self, parent = QModelIndex()):
    """
    \reimp

    The number of columns of the model, which is always set to `1` in this case.

    \return `1`
    """
    return 1

  def hasChildren(self, parent):
    if parent.isValid():
      item = self.itemFromIndex(parent)
      node = self.getNodeFromItem(item)
      if node != None:
        tmp = node.children()
        for i in tmp:
          if i.isDir() or i.hasChildren():
            return True
    elif self.root_item.index().internalId() == parent.internalId():
      return True
    else:
      return False
    return False

  def setCurrentIndex(self, old, new):
    self.data(old, Qt.BackgroundRole)
    self.data(old, Qt.ForegroundRole)
    self.data(new, Qt.BackgroundRole)
    self.data(new, Qt.ForegroundRole)
    self.currentIndex = new

  def flags(self, flag):
    """
    \reimp

    \returns the flag set in the model.
    """
    return (Qt.ItemIsSelectable | Qt.ItemIsEnabled | Qt.ItemIsUserCheckable)  

  def getParentNodeList(self, node):
    parents = []
    parent = node
    while parent.uid() != self.root_node.uid() and parent.uid() != self.vfsroot.uid():
      if parent != None:
        parents.append(parent)
        parent = parent.parent()
      else:
        break
    parents.reverse()
    return parents


  def Event(self, e):
    """
    Add e.value, which is a Variant containing a Node, in the tree (only if it has children
    or is a directory).

    """
    value = e.value
    if value == None:
      return
    node = value.value()
    if node == None:
      return
    if e.type == 0xde1:
      pass # call by main widget 
    else:
      self.emit(SIGNAL("refreshModel"), node)
   
  def removeNode(self, node):
    children = node.children()
    for child in children:
      self.removeNode(child)
    try:
      item = self.itemmap[node.uid()] 
      index = self.indexFromItem(item)
      self.removeRow(index.row(), index.parent())
      self.itemmap.pop(node.uid())
    except Exception as e :
      pass 
 
  def getItemFromNode(self, node):
    for nodeptr, item in self.itemmap.iteritems():
      if node.uid() == nodeptr:
        return item
    return None

  def refreshModel(self, node):
    # special case when adding new folder at root level
    uid = node.uid()
    if uid != self.root_node.uid() and uid not in self.__root_uids and node.parent().uid() == self.root_node.uid() and node.hasChildren():
      item = self.createItem(node)
      self.__root_uids.append(uid)
      self.root_item.appendRow(item)
    else:
      parents = self.getParentNodeList(node)
      for parent in parents:
        try:
          item = self.itemmap[parent.uid()]
          if item.rowCount() != 0:
            dircount = self.dirCount(parent)
            if item.rowCount() != dircount:
              new_nodes = self.getItemsToInsert(item, parent)
              if len(new_nodes) == (dircount - item.rowCount()):
                self.emit(SIGNAL("layoutAboutToBeChanged()"))
                self.insertRows(item, new_nodes)
                self.emit(SIGNAL("layoutChanged()"))
          else:
            children = sorted(parent.children(), cmp=locale.strcoll,
                              key=lambda Node: Node.name())
    	    self.emit(SIGNAL("layoutAboutToBeChanged()"))
            self.insertRows(item, children)
    	    self.emit(SIGNAL("layoutChanged()"))
        except KeyError:
          continue

  def getChildrenDirectories(self, parent):
    children = parent.children()
    childrendir = []
    for child in children:
      if child.isDir() or child.hasChildren():
        childrendir.append(child)
    return childrendir

  def getItemsToInsert(self, item, parent):
    children = self.getChildrenDirectories(parent)
    new_nodes = [] 
    for child in children:
      founded = False
      for childitem in range(0, item.rowCount()):
        node = self.getNodeFromItem(item.child(childitem))
        if node != None:
          if node.uid() == child.uid():
            founded = True
      if not founded:
        new_nodes.append(child)
    return new_nodes

  def getNodeFromItem(self, item):
    try:
      index = self.indexFromItem(item)
      node = self.getNodeFromIndex(index)
      return node
    except:
      return None

  def getNodeFromIndex(self, index):
    try:
      ptr = self.data(index, Qt.UserRole + 1).toULongLong()[0]
      node = self.VFS.getNodeById(ptr)
      if node == None:
        return None
      return node
    except:
      return None

  def dirCount(self, node):
    count = 0
    children = node.children()
    for child in children:
      if child.isDir() or child.hasChildren():
        count += 1
    return count

  def createItem(self, node):
    new_item = QStandardItem(node.name())
    new_item.setData(node.uid(), Qt.UserRole + 1)
    self.itemmap[node.uid()] = new_item
    return new_item

  def insertRows(self, item_parent, node_list):
    for child in node_list:
      if child.isDir() or child.hasChildren():
        new_item = self.createItem(child)
        item_parent.appendRow(new_item)

  def translation(self):
    """
    Used for translating the framework.
    """
    self.nameTr = self.tr('Name')

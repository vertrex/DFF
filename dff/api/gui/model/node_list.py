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


from PyQt4.QtCore import SIGNAL, QAbstractItemModel, QModelIndex, QVariant, Qt, QDateTime, QString, QSize
from PyQt4.QtGui import QColor, QIcon, QPixmap, QPainter, QStandardItemModel, QStandardItem, QApplication, QCursor, QPalette

from dff.api.types.libtypes import Variant, DateTime 
from dff.api.events.libevents import EventHandler
from dff.api.vfs.libvfs import VFS, ABSOLUTE_ATTR_NAME, VecNode, VLink
from dff.api.types.libtypes import typeId

from dff.api.gui.thumbnail import Thumbnailer

from functools import cmp_to_key
import locale

IMAGES = ["bmp", "gif", "jpg", "jpeg", "png", "psd", "tif", "BMP", "GIF", "JPG", "JPEG", "PNG", "PSD", "TIF"]
DOCUMENT = ["doc", "docx", "odt", "DOC", "DOCX", "ODT"]
SPREADSHEET = ["xlsx", "xls", "ods", "XLSX", "XLS", "ODF"]
VIDEO = ["wmv", "mpg", "mpg4", "mov", "avi", "3gp", "3ga", "asf", "3GA", "WMV", "MOV", "MPG", "MPG4", "AVI", "3GP"]
AUDIO = ["wav", "mp3", "wma", "m4a", "aif", "mid", "mpa", "WAV", "MP3", "WMA", "M4A", "AIF", "MID", "MPA"]
ARCHIVES = ["zip", "rar", "7zip", "gz", "ZIP", "RAR", "7ZIP", "GZ"]

class NodeListModel(QAbstractItemModel):
  def __init__(self, selection):
    QAbstractItemModel.__init__(self)
    self._list = []
    self._rows = []
    self._current_row = 0
    self._row_selected = 0
    self._thumb = True
    self._visible_rows = 0
    self._visible_cols = 0
    self._recursive = False
    self._root = None
    self.selection = selection
    if self.selection != None:
      self.connect(self.selection, SIGNAL("selectionChanged"), self.updateSelected)
    self.setDefaultAttributes()
    self.connectSignals()
    self.thumbnailer = Thumbnailer()
    self.connect(self.thumbnailer, SIGNAL("ThumbnailUpdate"), self.thumbnailUpdate)
    self.headerorder = {0:0}

  def thumbnailUpdate(self, node, pixmap):
     currentRow = self.currentRow()
     visibleRow = self.visibleRows()
     nodeList = self.list()
     currentList = nodeList[currentRow:currentRow + visibleRow]
     index = 0
     for cnode in currentList:
         if node.uid() == cnode.uid():
	   modelIndex = self.index(index, 0)
           self.emit(SIGNAL("dataChanged"), modelIndex, modelIndex)
         index += 1

  def _removeNode(self, node):
    children = node.children()
    for child in children:
      self._removeNode(child)
    for n in self._list:
      if n.uid() == node.uid():
        self._list.remove(n)
        self._row_selected = 0 
    for n in self._rows:
      if n.uid() == node.uid():
        self._rows.remove(n)      

  def removeNode(self, node): 
    try:
     if self._root == None or (self._root.path().find(node.parent().path()) != -1):
      self._row_selected = 0 
      self.changeList(node.parent(), self._recursive, None)
    except Exception as e :
      pass
    self._removeNode(node)

  def vfsNotification(self, node, eventType = None):
    if eventType == 0xde1:
      pass #called by noedelistwidget
    else:
      if node.parent().uid() == self._root.uid():
        self.changeList(self._root, self._recursive, self._list[self._row_selected])

  def updateSelected(self, count):
    self.emit(SIGNAL("layoutChanged()"))

  def connectSignals(self):
    self.connect(self, SIGNAL("appendList"), self.appendList)

  def setData(self, index, value, role):
    """
    \reimp

    Set the data which value is `value` at index `index` with role `role`.

    \return `True` if no error occured, `False` otherwise.
    """
    if not index.isValid():
      return QVariant()
    column = index.column()
    if role == Qt.CheckStateRole:
      if column == HNAME:
        node = self.VFS.getNodeById(index.internalId())
        if node == None:
          pass
        if value == Qt.Unchecked:
          if (node.uid(), 1) in self.checkedNodes:
            self.checkedNodes.remove((node.uid(), 1))
        else:
          self.checkedNodes.add((node.uid() , 1))
    QAbstractItemModel.setData(self, index, value, role)
    return True

  def changeList(self, root, recursive=False, selected=None):
    """ 
    Change the current list based on root children.
    If recursive is True, the list will be based on the recursion
    If selected is provided it will automatically be the current row
    """
    if root != None:
      self._root = root
      self._recursive = recursive
      self._list = []
      self.row_selected = 0
      self._current_row = 0
      if recursive:
        self._fillRecursiveList(root.children())
      else:
        self._list = root.children()
      self.sort(self.headerorder.keys()[0], self.headerorder[self.headerorder.keys()[0]])
      idx = 0
      if not recursive and selected != None:
        for i in xrange(0, len(self._list)):
          if selected.uid() == self._list[i].uid():
            idx = i
            break
      self.emit(SIGNAL("maximum"), len(self._list))
      if idx > self._current_row + self._visible_rows:
        self._current_row = idx
        self.select(0)
      else:
        self.select(idx)
      self.emit(SIGNAL("changeList"))

  def currentRoot(self):
    return self._root

  def recursive(self):
    return self._recursive

  def updateList(self, nodes, recursive=False, selected=None):
    """ 
    Update list from an existing one.
    Useful when switching from filtered view
    """
    if len(nodes):
      self._recursive = recursive
      self._list = nodes
      if not recursive and selected != None:
        for i in xrange(0, len(self._list)):
          if selected.uid() == self._list[i].uid():
            self._current_row = i
            self.row_selected = i
            break
      self.emit(SIGNAL("maximum"), len(self._list))
      self.select(0)
      self.emit(SIGNAL("changeList"))

  def _fillRecursiveList(self, nodes):
    for node in nodes:
      self._list.append(node)
      if node.hasChildren():
        self._fillRecursiveList(node.children())

  def appendList(self, node):
    """
    Append a new node to the existing model's list and emit an appended signal with the new size.
    """
    if node != None:
      try:
        self._list.append(node)
        self.emit(SIGNAL("nodeAppended"))
        self.emit(SIGNAL("maximum"), len(self._list))
        self.refresh(self._current_row)
      except:
        print "Error while appending node"
        return

  def defaultAttributes(self):
    return self._default_attributes

  def clearList(self):
    self.emit(SIGNAL("clearList"))
    self._recursive = False
    self._list = []
    self._current_row = 0
    self.refresh(self._current_row)

  def columnCount(self, index):
    attrs = self.availableAttributes()
    return len(attrs)

  def data(self, index, role):
    attributes = self.availableAttributes()
    if not index.isValid():
      return QVariant()
    if index.row() > len(self._list) or index.row() < 0:
      return QVariant()
    try:
      node = self._rows[index.row()]
    except:
      return QVariant()
    if role == Qt.DisplayRole :
      attrpath = str(unicode(attributes[index.column()]).encode('utf-8'))
      if attrpath == "name":
          return QVariant(QString.fromUtf8(node.name()))
      elif attrpath == "size":
          return QVariant(node.size())
      elif attrpath == "extension":
          return QVariant(QString.fromUtf8(node.extension()))
      elif attrpath == "path":
          if isinstance(node, VLink):
            return QVariant(QString.fromUtf8(node.linkPath()))
          else:
            return QVariant(QString.fromUtf8(node.path()))
      elif attrpath == "absolute":
          if isinstance(node, VLink):
            return QVariant(QString.fromUtf8(node.linkAbsolute()))
          else:
           return QVariant(QString.fromUtf8(node.absolute()))
      elif attrpath == "module":
	  if node.fsobj():
            return QVariant(QString.fromUtf8(node.fsobj().name))
          return QVariant()
      elif attrpath == "has children":
          if isinstance(node, VLink):
            return QVariant(node.linkHasChildren())
          else:
            return QVariant(node.hasChildren())
      elif attrpath == "child count":
          if isinstance(node, VLink):
            return QVariant(node.linkChildCount())
          else:
            return QVariant(node.childCount())
      elif attrpath == "is deleted":
          return QVariant(node.isDeleted())
      elif attrpath == "tags":
          #Special case tag use a delegate to draw boxes
          return QVariant()
      else:
	try :
          val = node.attributesByName(attrpath, ABSOLUTE_ATTR_NAME)
	except Exception as e:
	   print "NodeListModel data can't get attribute " + attrpath + " by name " + str(e)
	   return QVariant()
        if len(val) == 1:
          if val[0].type() == typeId.DateTime:
            dateTime = val[0].value()
            if dateTime:
              try:
                return QVariant(str(dateTime))
              except:
                return QVariant()
          elif val[0].type() == typeId.String:
            return QVariant(QString.fromUtf8(val[0].value()))
          else:
            return QVariant(val[0].value())
        else:
          return QVariant()
    if role == Qt.ToolTipRole :
      return QVariant(QString.fromUtf8(node.name()))

    # Display icons
    if (role == Qt.DecorationRole) and (attributes[index.column()] == "name"):
      pixmap = None
      if self._thumb:
	if self.thumbnailer.isThumbnailable(node):
	  pixmap = self.thumbnailer.generate(node)
          if pixmap is None:
	    pixmap = QPixmap(":file_temporary.png")
      if not pixmap:
        pixmap = self.getIconPixmap(node)
        if not pixmap:
          pixmap = QPixmap(node.icon())
        
        if isinstance(node, VLink):
          pixmap = pixmap.scaled(QSize(128, 128), Qt.KeepAspectRatio)
          painter = QPainter(pixmap)
          linkPixmap = QPixmap(":vlink") 
          painter.drawPixmap(0, 0, linkPixmap)
          painter.end()

	elif node.hasChildren():
          try:
            pfsobj = node.children()[0].fsobj().this
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
      if index.row() == self.activeSelection():
        palette = QPalette().color(QPalette.Highlight)
        return QVariant(QColor(palette))
    if role == Qt.ForegroundRole:
      if index.row() == self.activeSelection():
        palette = QPalette().color(QPalette.HighlightedText)
        return QVariant(QColor(palette))
      if node.isDeleted():
        return  QVariant(QColor(Qt.red))

    if (role == Qt.CheckStateRole) and (attributes[index.column()] == "name"):
      if node.uid() in self.selection.get():
        return Qt.Checked
      else:
        return Qt.Unchecked
    return QVariant()

  def setThumb(self, state):
    self._thumb = state

  def getIconPixmap(self, node):
    ext = self.getExtension(node)
    if ext != None:
      if ext in IMAGES:
        return QPixmap(":image.png")
      elif ext in AUDIO:
        return QPixmap(":sound.png")
      elif ext == "pdf":
        return QPixmap(":pdf.png")
      elif ext in DOCUMENT:
        return QPixmap(":document.png")
      elif ext in VIDEO:
        return QPixmap(":video.png")
      elif ext in ARCHIVES:
        return QPixmap(":zip")
      elif ext in SPREADSHEET:
        return QPixmap(":spreadsheet.png")
      else:
        return None

  def getExtension(self, node):
    name = node.name()
    sext = name.split(".")
    if len(sext) > 1:
      return sext[len(sext) - 1]
    else:
      return None

  def getNode(self, row):
    try:
      node = self._list[row]
      if node:
        return node
      else:
        return None
    except IndexError:
      return None

  def index(self, row, column, parent = QModelIndex()):
    if not self.hasIndex(row, column, parent):
     return QModelIndex()
    if not parent.isValid():
      index = self.createIndex(row, column, self._rows[row])
      return index
    return QModelIndex()

  def parent(self, index):
    return QModelIndex()

  def refresh(self, start):
    llist = len(self._list)
    if start < 0:
      rstart = 0
    elif (start >= llist):
      # End of list
      rstart = llist - (self._visible_rows)
      if rstart < 0:
        rstart = 0
    # elif ((llist - start) <= self._visible_rows + 1):
    #   rstart = self._current_row
    #   if rstart < 0:
    #     rstart = 0
    else:
      rstart = start

    # End of List range
    if (rstart + self._visible_rows) > len(self._list):
      end = len(self._list)
    else:
      end = rstart + self._visible_rows + 1
    self.resetDisplay()
    try:
      tmplist = self._list[rstart:end]
    except IndexError:
      return
    try:
      for nodeId in range(0, len(tmplist)):
        if tmplist[nodeId] != None:
          self._rows.append(tmplist[nodeId])
      self.emit(SIGNAL("layoutAboutToBeChanged()"))
      self.emit(SIGNAL("layoutChanged()"))

      if self._current_row >= 0:
        self._current_row = rstart
      else:
        self._current_row = 0
      self.emit(SIGNAL("current"), self._current_row)
    except IndexError:
      print "Error while refreshing model"
      pass

  def resetDisplay(self):
    if len(self._rows) > 0:
      self._rows = []
      self.emit(SIGNAL("layoutAboutToBeChanged()"))
      self.emit(SIGNAL("layoutChanged()"))

  def rowCount(self, parent = None):
    return len(self._rows)

  def currentRow(self):
    return self._current_row

  def size(self):
    return len(self._list)

  def setVisibleRows(self, rows):
    self._visible_rows = rows + 1
    self.emit(SIGNAL("maximum"), len(self._list))
    if self._visible_rows > self.size():
      self.emit(SIGNAL("hideScroll"))
    self.refresh(self._current_row)

  def visibleRows(self):
    return self._visible_rows

  def seek(self, position, where = 0):
    if where == 0:
      self.refresh(position)
    elif where == 1:
      pos = self._current_row + position
      self.refresh(pos)
    else:
      self.refresh(self._current_row)

  def select(self, row):
    """
    Set absolute selected row id in model's list
    """
    absrow = self._current_row + row
    try:
      node = self._list[absrow]
      self._row_selected = absrow
      self.refresh(self._current_row)
      self.emit(SIGNAL("nodeListClicked"), Qt.NoButton)
      return True
    except:
      return False

  def activeSelection(self):
    """
    Return relative selected row id
    """
    return self._row_selected - self._current_row

  def currentNode(self):
    try:
      node = self._list[self._row_selected]
      return node 
    except:
      return None

  def nodeSelected(self):
    nodes = []
    nodes.append(self._list[self._row_selected])
    return nodes

  def setDefaultAttributes(self):
    self._default_attributes = ["name", "size","tags", "path", "extension", "absolute", "module", "has children", "child count", "is deleted"]
    self.setSelectedAttributes(["name", "size", "tags", "path"])

  def setSelectedAttributes(self, attributes):
    self._selected_attributes = attributes
    self.refresh(self._current_row)

  def selectedAttributes(self):
    return self._selected_attributes

  def availableAttributes(self):
    attrs = self.selectedAttributes()[:]
    return attrs

  def setHeaderData(self, section, orientation, value, role):
    self.emit(SIGNAL("layoutAboutToBeChanged()"))
    QAbstractItemModel.setHeaderData(self, section, orientation, value, role)
    self.emit(SIGNAL("layoutChanged()"))

  def headerData(self, section, orientation, role=Qt.DisplayRole):
    if role != Qt.DisplayRole:
      return QVariant()
    if orientation == Qt.Horizontal:
      attrs = self.availableAttributes()
      return QVariant(attrs[section])

  def sort(self, column, order):
    """
    Sort model's list and check.
    """
    self.headerorder.clear()
    self.headerorder[column] = order
    QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
    if order == Qt.DescendingOrder:
      Reverse = True
    else:
      Reverse = False
    attrs = self.availableAttributes()
    try:
      attrpath = str(unicode(attrs[column]).encode('utf-8'))
    except IndexError:
      QApplication.restoreOverrideCursor()
      self.headerorder.clear()
      self.headerorder = {0:0}
      self.refresh(0)
      self.select(0)
      return

    if isinstance(self._list, VecNode):
      tmplist = []
      for i in range(0, len(self._list)):
        tmplist.append(self._list[i])
      self._list = tmplist
    if attrpath in self._default_attributes:
      if attrpath == "name":
        self._list = sorted(self._list, cmp=locale.strcoll,
                           key=lambda Node: Node.name(), 
                           reverse=Reverse)
      elif attrpath == "size":
        self._list = sorted(self._list,
                           key=lambda Node: Node.size(),
                           reverse=Reverse)
      elif attrpath == "extension":
        self._list = sorted(self._list, cmp=locale.strcoll,
                           key=lambda Node: Node.extension(),
                           reverse=Reverse)
      elif attrpath == "path":
        self._list = sorted(self._list, cmp=locale.strcoll,
                           key=lambda Node: Node.path(),
                           reverse=Reverse)
      elif attrpath == "absolute":
 	self._list = sorted(self._list, cmp=locale.strcoll,
			     key=lambda Node: Node.absolute(),
			     reverse=Reverse)
      elif attrpath == "module":
	self._list = sorted(self._list, cmp=self.cmp_fsobj, 
			    key=lambda Node: Node.fsobj(),
			    reverse=Reverse)
      elif attrpath == "has children":
	self._list = sorted(self._list, key=lambda Node: Node.hasChildren(), reverse=Reverse)
      elif attrpath == "child count":
	self._list = sorted(self._list, key=lambda Node: Node.childCount(), reverse=Reverse)
      elif attrpath == "is deleted": 
	self._list = sorted(self._list, key=lambda Node: Node.isDeleted(), reverse=Reverse)
      elif attrpath == "tags":
        self._list = sorted(self._list,
                             key=lambda Node: len(Node.tags()),
                             reverse=Reverse)
    else:
        self._list = sorted(self._list,
                             cmp=self.cmp_none, key=lambda Node: self.attributesByName(Node, attrpath, ABSOLUTE_ATTR_NAME),
                             reverse=Reverse)
    QApplication.restoreOverrideCursor()
    self.refresh(0)
    self.select(0)
    return

  def cmp_fsobj(self, x, y):
     try:
	return cmp(x.name, y.name)
     except AttributeError:
        if x == y == None:
	  return 0
        elif x == None:
	  return -1
	elif y is None:
	  return 1

  def cmp_none(self,x, y):
     try:
	return cmp(x, y)
     except TypeError: 
	if x == None and y == None:
	  return 0
        elif x == None:
	  return -1
	elif y is None:
	  return 1
     except  ValueError:
       if x is None and y is None:
        return 0
       elif x is None:
         return -1
       elif y is None:
         return 1  

  def attributesByName(self, node, attrpath, ABSOLUTE_ATTR_NAME):
      val = node.attributesByName(attrpath, ABSOLUTE_ATTR_NAME)
      if len(val) == 1:
        if val[0].type() == typeId.DateTime:
          return DateTime(val[0].value()) #must copy because or set variant this own to false because rc_variant store DateTime*  that is deleted at function return
        else:
          val = val[0].value()
          return val

  def list(self):
    return self._list

  def allListChecked(self):
    checked = self.selection.get()
    for node in self._list:
      if not node.uid() in checked:
        return False
    return True

  def selectAll(self):
    for node in self._list:
      self.selection.add(node)

  def unselectAll(self):
    for node in self._list:
      self.selection.rm(node)


class TimeLineNodeListModel(NodeListModel):
  def __init__(self, selection):
    NodeListModel.__init__(self, selection)

  def thumbnailUpdate(self, node, pixmap):
     currentRow = self.currentRow()
     visibleRow = self.visibleRows()
     nodeList = self.list()
     currentList = nodeList[currentRow:currentRow + visibleRow]
     index = 0
     for cnode in currentList:
         if node.uid() == cnode.node().uid():
	   modelIndex = self.index(index, 0)
           self.emit(SIGNAL("dataChanged"), modelIndex, modelIndex)
         index += 1

  def _removeNode(self, node):
    children = node.children()
    for child in children:
      self._removeNode(child)
    for n in self._list:
      if n.node().uid() == node.uid():
        self._list.remove(n)
        self._row_selected = 0 
    for n in self._rows:
      if n.node().uid() == node.uid():
        self._rows.remove(n)      

  def updateList(self, nodes, recursive=False, selected=None):
    """ 
    Update list from an existing one.
    Useful when switching from filtered view
    """
    if len(nodes):
      self._recursive = recursive
      self._list = nodes
      if not recursive and selected != None:
        for i in xrange(0, len(self._list)):
          if selected.uid() == self._list[i].node().uid():
            self._current_row = i
            self.row_selected = i
            break
      self.emit(SIGNAL("maximum"), len(self._list))
      self.select(0)
      self.emit(SIGNAL("changeList"))

  def data(self, index, role): #XXX
    attributes = self.availableAttributes()
    if not index.isValid():
      return QVariant()
    if index.row() > len(self._list) or index.row() < 0:
      return QVariant()
    try:
      timeLineNode = self._rows[index.row()]
      node = timeLineNode.node()
    except:
      return QVariant()
    if role == Qt.DisplayRole :
      attrpath = str(unicode(attributes[index.column()]).encode('utf-8'))
      if attrpath == "name":
          return QVariant(QString.fromUtf8(node.name()))

      elif attrpath == "time":
         try:
           return QVariant(QString.fromUtf8(str(timeLineNode.attribute())))
         except:
           return QVariant()
      elif attrpath == "time attribute":
          return QVariant(QString.fromUtf8(timeLineNode.attributeName()))

      elif attrpath == "size":
          return QVariant(node.size())
      elif attrpath == "extension":
          return QVariant(QString.fromUtf8(node.extension()))
      elif attrpath == "path":
          if isinstance(node, VLink):
            return QVariant(QString.fromUtf8(node.linkPath()))
          else:
            return QVariant(QString.fromUtf8(node.path()))
      elif attrpath == "absolute":
          if isinstance(node, VLink):
            return QVariant(QString.fromUtf8(node.linkAbsolute()))
          else:
           return QVariant(QString.fromUtf8(node.absolute()))
      elif attrpath == "module":
	  if node.fsobj():
            return QVariant(QString.fromUtf8(node.fsobj().name))
          return QVariant()
      elif attrpath == "has children":
          if isinstance(node, VLink):
            return QVariant(node.linkHasChildren())
          else:
            return QVariant(node.hasChildren())
      elif attrpath == "child count":
          if isinstance(node, VLink):
            return QVariant(node.linkChildCount())
          else:
            return QVariant(node.childCount())
      elif attrpath == "is deleted":
          return QVariant(node.isDeleted())
      elif attrpath == "tags":
          #Special case tag use a delegate to draw boxes
          return QVariant()
      else:
	try :
          val = node.attributesByName(attrpath, ABSOLUTE_ATTR_NAME)
	except Exception as e:
	   print "NodeListModel data can't get attribute " + attrpath + " by name " + str(e)
	   return QVariant()
        if len(val) == 1:
          if val[0].type() == typeId.DateTime:
            dateTime = val[0].value()
            if dateTime:
              return QVariant(str(dateTime))
          elif val[0].type() == typeId.String:
            return QVariant(QString.fromUtf8(val[0].value()))
          else:
            return QVariant(val[0].value())
        else:
          return QVariant()
    if role == Qt.ToolTipRole :
      return QVariant(QString.fromUtf8(node.name()))

    # Display icons
    if (role == Qt.DecorationRole) and (attributes[index.column()] == "name"):
      pixmap = None
      if self._thumb:
	if self.thumbnailer.isThumbnailable(node):
	  pixmap = self.thumbnailer.generate(node)
          if pixmap is None:
	    pixmap = QPixmap(":file_temporary.png")
      if not pixmap:
        pixmap = self.getIconPixmap(node)
        if not pixmap:
          pixmap = QPixmap(node.icon())
        
        if isinstance(node, VLink):
          pixmap = pixmap.scaled(QSize(128, 128), Qt.KeepAspectRatio)
          painter = QPainter(pixmap)
          linkPixmap = QPixmap(":vlink") 
          painter.drawPixmap(0, 0, linkPixmap)
          painter.end()

	elif node.hasChildren():
          try:
            pfsobj = node.children()[0].fsobj().this
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
      if index.row() == self.activeSelection():
        palette = QPalette().color(QPalette.Highlight)
        return QVariant(QColor(palette))
    if role == Qt.ForegroundRole:
      if index.row() == self.activeSelection():
        palette = QPalette().color(QPalette.HighlightedText)
        return QVariant(QColor(palette))
      if node.isDeleted():
        return  QVariant(QColor(Qt.red))

    if (role == Qt.CheckStateRole) and (attributes[index.column()] == "name"):
      if node.uid() in self.selection.get():
        return Qt.Checked
      else:
        return Qt.Unchecked
    return QVariant()


  def setDefaultAttributes(self):
    self._default_attributes = ["name", "size", "tags", "path", "extension", "absolute", "module", "has children", "child count", "is deleted"]
    self.setSelectedAttributes(["name", "time", "time attribute", "tags", "size", "path"])

  def setSelectedAttributes(self, attributes):
    self._selected_attributes = attributes
    try:
      self.refresh(self._current_row)
    except AttributeError:
      self.refresh(0)

  def selectedAttributes(self):
    return self._selected_attributes

  def sort(self, column, order):
    return

  def getNode(self, row):
    try:
      node = self._list[row].node()
      if node:
        return node
      else:
        return None
    except IndexError:
      return None



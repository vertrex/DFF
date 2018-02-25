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
import re

from PyQt4.QtCore import SIGNAL, QAbstractItemModel, QModelIndex, QVariant, Qt, QDateTime, QSize, QString, Qt
from PyQt4.QtGui import QColor, QIcon, QImage, QImageReader, QPixmap, QPixmapCache, QStandardItemModel, QStandardItem, QStyledItemDelegate, QBrush, QPen, QPalette, QPainter
from PyQt4 import QtCore

from dff.api.module.manager import ModuleProcessusManager

# USED FOR DETECT REGISTRY TYPE
HKLM = ["^SYSTEM$", "^SOFTWARE$", "^SAM$", "^SECURITY$"]
HKU = ["^NTUSER.DAT$", "^DEFAULT$", "^USRCLASS.DAT$"]
REPAIR = "WINDOWS/repair/"
LOG = ".*.log$"
ALT = ".*.alt$"
SAVE = ".*.sav$"
# USER ROLES


class RegTreeModel(QStandardItemModel):
  def __init__(self, __parent = None):
    QStandardItemModel.__init__(self, __parent)
    self.__parent = __parent
    self.regmap = {}
    self.indexmap = {}
    self.__columnCount = 0
    if self.createRegMap():
      self.createRootItems()


  def hasSubKeys(self, key):
    return len(key.subkeys)


  def createRegMap(self):
    processusManager = ModuleProcessusManager()
    regm = processusManager.get('winreg')
    if len(regm.registry) > 0:
      self.__columnCount = 1
      self.hives = regm.registry
      self.manager = regm
      for key, values in self.hives.iteritems():
        try:
          h = key.getHive()
          iterator = h.iterator
          rtype, sourcenode = values
          rtype = self.RegType(sourcenode)
          if rtype != None:
            try:
              machine = self.regmap[sourcenode.fsobj().uid()]
            except:
              machine = self.regmap[sourcenode.fsobj().uid()] = {}
            try:
              regsource = machine[rtype]
            except:
              regsource = machine[rtype] = []
            regsource.append(key)
          del(h)
        except:
          del(h)
          pass
      return True
    else:
      return False
    return False


  def createRootItems(self):
    self.root_item = self.invisibleRootItem()
    for machine_fsobjuid, regmodules in self.regmap.iteritems():
      machineitem = regItem("Computer" + str(machine_fsobjuid))
      machineitem.root = True
      machineitem.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
      self.root_item.appendRow(machineitem)
      for rtype, regmodulist in regmodules.iteritems():
        typeitem = regItem(rtype)
        typeitem.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
        machineitem.appendRow(typeitem)
        for regmodule in regmodulist:
          try:
            h = regmodule.getHive()
            iterator = h.iterator
            keypath = iterator.current_path()

            if rtype == "HKEY_USERS":
              if (re.search("documents and settings", h.node.absolute(), re.IGNORECASE) or\
                    re.search("users", h.node.absolute(), re.IGNORECASE)) and not \
                    re.match("usrclass.dat", h.node.name(), re.IGNORECASE):
                name = h.node.parent().name()
              else:
                name = h.node.name()
            else:
              name = h.node.name()
            item = regItem(name, proc=regmodule,path=keypath)
            item.setChildren(len(iterator.current_key().subkeys))
            item.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
            del(h)
            typeitem.appendRow(item)
          except:
            pass


  def hasChildren(self, parent):
      if parent.isValid():
        item = self.itemFromIndex(parent)
        if (item.children > 0) or (item.proc == None):
          return True
      elif self.__columnCount > 0 and self.root_item.index().internalId() == parent.internalId():
          return True
      else:
          return False
      return False


  def data(self, index, role):
      if not index.isValid():
        return QVariant()
      item = self.itemFromIndex(index)
      if role == Qt.DisplayRole :
        return QVariant(item.text())

      if role == Qt.DecorationRole:
        if item.root:
          icon = QPixmap(":dev_desktop.png")
          return QVariant(QIcon(icon))
        else:
          icon = QPixmap(":folder.png")
          return QVariant(QIcon(icon))


  def columnCount(self, parent = QModelIndex()):
    return self.__columnCount


  def createItem(self, current_path, module, key):
    p = current_path[:]
    p.append(unicode(key.name))
    item = regItem(QString.fromUtf8(key.name), proc=module,path=p)
    item.setChildren(len(key.subkeys))
    item.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
    return item


  def refreshTree(self, index):
      item = self.itemFromIndex(index)
      if not item.expanded:
          rhive = item.getHive()
          if rhive != None:
            hive = rhive.hive
            path = item.path
            if len(path) == 1:
              subkeys = hive.root.subkeys
            else:
              subkeys = hive.subtree(path[1:]).current_key().subkeys
            if len(subkeys) > 0:
              item_list = []
              for key in subkeys:
                item_list.append(self.createItem(path, item.proc, key))
            if len(item_list):
    	      self.emit(SIGNAL("layoutAboutToBeChanged()"))
              item.appendRows(item_list)
    	      self.emit(SIGNAL("layoutChanged()"))
            item.expanded = True
            item.deleteHive()


  def selectKey(self, index):
    if index.isValid():
      item = self.itemFromIndex(index)
      rhive = item.getHive()
      path = item.path
      hive = rhive.hive
      if len(path) == 1:
          key = hive.root
      else:
          key = hive.subtree(path[1:]).current_key()
      self.emit(SIGNAL("keyItemSelected"), item)
      self.emit(SIGNAL("keySelected"), rhive, key)
      

  def RegType(self, node):
    try:
      if re.search(REPAIR, node.absolute(), re.IGNORECASE):
        return "HKEY_REPAIR"
      elif re.match(LOG, node.name(), re.IGNORECASE):
        return "HKEY_LOG"
      elif re.match(SAVE, node.name(), re.IGNORECASE):
        return "HKEY_SAVE"
      elif re.match(ALT, node.name(), re.IGNORECASE):
        return "HKEY_ALT"
      else:
        for hname in HKLM:
          if re.match(hname, node.name(), re.IGNORECASE):
            return "HKEY_LOCAL_MACHINE"
        for hname in HKU:
          if re.match(hname, node.name(), re.IGNORECASE):
            return "HKEY_USERS"
        for hname in HKUCL:
          if re.match(hname, node.name(), re.IGNORECASE):
            return "HKEY_CLASSES"
      return "HKEY_OTHERS"
    except:
      return None
    return None


class regItem(QStandardItem):
  def __init__(self, name, proc=None, path=None):
    QStandardItem.__init__(self, name)
    self.proc = proc
    self.path = path
    self.hive = None
    self.children = 0
    self.expanded = False
    self.root = False

  def setChildren(self, count):
    self.children = count

  def getHive(self):
    if self.proc != None:
      self.hive = self.proc.getHive()
      return self.hive
    else:
      return None

  def deleteHive(self):
    del(self.hive)

#    self.hive = None
  

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
#  Frederic Baguelin <fba@digital-forensic.org>
# 
import sys, time

from dff.api.vfs.libvfs import ABSOLUTE_ATTR_NAME, VFS
from dff.api.filters.libfilters import Filter

from PyQt4.QtCore import QObject, SIGNAL
from PyQt4.QtGui import QApplication

class AbstractStatusModel(QObject):
  def __init__(self):
    QObject.__init__(self)
    self._order = []
    self._status = {}

  def count(self):
    return len(self._order)

  def resetStatus(self):
    for status in self._status.itervalues():
      status.reset()
    self.notify()

  def process(self, node):
    if node is not None:
      for status in self._status.itervalues():
        status.process(node)
    self.notify()

  def notify(self):
    for status in self._status.itervalues():
      status.notify()

  def status(self, idx):
    if idx < len(self._order) and self._status.has_key(self._order[idx]):
      return self._status[self._order[idx]]

  def removeStatus(self, idx):
    if idx < len(self._order) and self._status.has_key(self._order[idx]):
      del self._status[self._order[idx]]
      del self._order[idx]

  def format(self, idx):
    if idx < len(self._order) and self._status.has_key(self._order[idx]):
        return self._status[self._order[idx]].format()
    else:
      return {}

  def styles(self, idx):
    if idx < len(self._order) and self._status.has_key(self._order[idx]):
        return self._status[self._order[idx]].styles()
    else:
      return {}

  def data(self, idx):
    if idx < len(self._order) and self._status.has_key(self._order[idx]):
        return self._status[self._order[idx]].data()
    else:
      return {}

class ViewStatusModel(AbstractStatusModel):
  def __init__(self, model, selection):
    AbstractStatusModel.__init__(self)
    self._model = model
    self._order = ["Nodes", "Files", "Folders", "Selected"]
    self._status = {"Nodes": NodesCounterModel(),
                    "Files": FilesCounterModel(),
                    "Folders": FoldersCounterModel(),
                    "Selected": SelectedCounterModel(selection)}
    self.connect(model, SIGNAL("changeList"), self.processList)
    self.connect(model, SIGNAL("appendList"), self.process)
    self.connect(model, SIGNAL("clearList"), self.clearList)

  def clearList(self):
    for status in self._status.itervalues():
      status.setRecursive(False)
      status.reset()
    self.notify()

  def processList(self):
    self.resetStatus()
    _list = self._model.list()
    recursive = self._model.recursive()
    if len(_list): 
      for i in xrange(0, len(_list)):
        for status in self._status.itervalues():
          status.setRecursive(recursive)
          status.process(_list[i])
    self.notify()

class TimeLineNodeViewStatusModel(ViewStatusModel):
  def __init__(self, model, selection):
    AbstractStatusModel.__init__(self)
    self._model = model
    self._order = ["Nodes", "Files", "Folders", "Selected"]
    self._status = {"Nodes": NodesCounterModel(),
                    "Files": FilesCounterModel(),
                    "Folders": FoldersCounterModel(),
                    "Selected": SelectedCounterModel(selection)}
    self.connect(model, SIGNAL("changeList"), self.processList)
    self.connect(model, SIGNAL("appendList"), self.process)
    self.connect(model, SIGNAL("clearList"), self.clearList)

  def clearList(self):
    for status in self._status.itervalues():
      status.setRecursive(False)
      status.reset()
    self.notify()

  def processList(self):
    self.resetStatus()
    _list = self._model.list()
    recursive = self._model.recursive()
    if len(_list): 
      for i in xrange(0, len(_list)):
        for status in self._status.itervalues():
          status.setRecursive(recursive)
          status.process(_list[i].node())
    self.notify()

class NodeStatusModel(AbstractStatusModel):
  def __init__(self, emiter):
    AbstractStatusModel.__init__(self)
    self._order = ["Type"]
    self._status = {"Type": AttributeStatusModel("Type", "type")}
    #self._order = ["Mime", "First Cluster"]
    #self._status = {"Mime": AttributeStatusModel("Mime", "type.magic mime"),
    #                "First Cluster": AttributeStatusModel("First Cluster", "Fat File System.first cluster")}
    self.connect(emiter, SIGNAL("currentNode"), self.process)

class AbstractStatusItemModel(QObject):
  def __init__(self, key="", fmt="", styles=""):
    QObject.__init__(self)
    self._key = key
    self._format = fmt
    self._styles = styles
    self._recursive = False

  def notify(self):
    self.emit(SIGNAL("updateStatus"))

  def process(self, node):
    raise NotImplementedError

  def setRecursive(self, recursive):
    self._recursive = recursive

  def reset(self):
    raise NotImplementedError

  def format(self):
    return self._format

  def styles(self):
    return self._styles

  def data(self):
    return {}


class DefaultCounter(AbstractStatusItemModel):
  def __init__(self, key):
    AbstractStatusItemModel.__init__(self, key,
                                 fmt="{key}: {total} ({regular} + {deleted})",
                                 styles={"key": "font-size: 8pt; font-weight: bold", "deleted": "color: red"})
    self._regular = 0
    self._deleted = 0

  def reset(self):
    self._regular = 0
    self._deleted = 0

  def data(self):
    return {"key": self._key, "total": self._regular+self._deleted, 
            "regular": self._regular, "deleted": self._deleted}

class NodesCounterModel(DefaultCounter):
  def __init__(self):
    DefaultCounter.__init__(self, "Node")

  def process(self, node):
    if node.isDeleted():
      self._deleted += 1
    else:
      self._regular += 1

class FilesCounterModel(DefaultCounter):
  def __init__(self):
    DefaultCounter.__init__(self, "Files")

  def process(self, node):
    if node.isFile():
      if node.isDeleted():
        self._deleted += 1
      else:
        self._regular += 1  

class FoldersCounterModel(DefaultCounter):
  def __init__(self):
    DefaultCounter.__init__(self, "Folders")

  def process(self, node):
    if node.isDir():
      if node.isDeleted():
        self._deleted += 1
      else:
        self._regular += 1  

class SelectedCounterModel(AbstractStatusItemModel):
  def __init__(self, selection):
    AbstractStatusItemModel.__init__(self, "Selected",
                                 fmt="{key}: {current} / {total}",
                                 styles={"key": "font-size: 8pt; font-weight: bold"})
    self.__selection = selection
    self.__count = 0
    self.connect(selection, SIGNAL("selectionChanged"), self.updateSelected)

  def updateSelected(self, count):
    if self._recursive:
      self.__count += count
    else:
      if count < 0:
        self.__count -= 1
      else:
        self.__count += 1
    if self.__count < 0:
      self.__count = 0
    self.notify()
  
  def process(self, node):
    if self.__selection.isChecked(node):
      self.__count += 1
  
  def reset(self):
    self.__count = 0

  def data(self):
    return {"key": self._key, "current": self.__count, "total": len(self.__selection._selection)}

class AttributeCounterModel(AbstractStatusItemModel):
  def __init__(self, key, attribute, value=None):
    AbstractStatusItemModel.__init__(self, key)
    self._attribute = attribute
    self._value = value
    self._count = 0

  def process(self, node):
    attr = node.attributesByName(self._attribute, ABSOLUTE_ATTR_NAME)
    if len(attr):
      if self.__value:
        attr = attr[0].value()
        if attr == value:
          self._count += 1
      else:
        self._count += 1

  def reset(self):
    self._count = 0

  def data(self):
    return {"key": self._key, "value": self._count}


class RangeStatusModel(AbstractStatusItemModel):
  def __init__(self, attribute):
    self.__attribute = attribute
    self.__minimum = sys.maxsize
    self.__maximum = -sys.maxsize

  def process(self, node):
    attr = node.attributesByName(attribute, ABSOLUTE_ATTR_NAME)
    if len(attr):
      attr = attr[0]
      if attr.type() == DateTime:
        val = attr.value().toPyDateTime() 
        ts = time.mktime(val)
        if ts > self.__maximum:
          self.__maximum = ts
        if ts < self.__minimum:
          self.__minimum = ts
      elif attr.type() in [typeId.Int16, typeId.UInt16, typeId.Int32, typeId.UInt32, typeId.Int64, typeId.UInt64]:
        val = attr.value()
        if val < minimum:
          minimum = val
        elif val > maximum:
          maximum = val

  def reset(self):
    self.__minimum = sys.maxsize
    self.__maximum = -sys.maxsize

  def data(self):
    return (self.__minimum, self.__maximum)


class AttributeStatusModel(AbstractStatusItemModel):
  def __init__(self, key, attribute, fmt="", styles=""):
    AbstractStatusItemModel.__init__(self, key,
                                 fmt="{key}: {value}",
                                 styles={"key": "font-size: 8pt; font-weight: bold"})
    self.__attribute = attribute
    self.__value = ""

  def process(self, node):
    attr = node.attributesByName(self.__attribute, ABSOLUTE_ATTR_NAME)
    if len(attr):
      attr = attr[0].value()
      self.__value = str(attr)

  def reset(self):
    self.__value = ""

  def data(self):
    if self.__value != "":
      return {"key": self._key, "value": self.__value}
    else:
      return {"key": self._key, "value": "N/A"}

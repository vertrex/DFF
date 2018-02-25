# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
#
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

import sys

from PyQt4 import QtCore, QtGui, QtXml

from PyQt4.QtCore import SIGNAL, QVariant, QAbstractItemModel, Qt, QModelIndex
from PyQt4.QtGui import QWidget, QTreeView
from PyQt4.QtXml import QDomDocument, QDomNode


class EvtxTree(QWidget):
      def __init__(self, xml, parent = None):
          QWidget.__init__(self, None)
          self.doc = QDomDocument()
          if self.doc.setContent(xml) == False:
              print "Something is wrong"
              return
          self.model = DomModel(self.doc, self)
          parent.view.setModel(self.model)

class DomModel(QAbstractItemModel):
    def __init__(self, document, parent = None):
        QAbstractItemModel.__init__(self, parent)
        self.domDocument = document
        self.rootItem = DomItem(self.domDocument, 0)

    def columnCount(self, parent):
        return 3
    
    def data(self, index, role):
        if not index.isValid():
            return QVariant()

        if role != Qt.DisplayRole:
            return QVariant()

        item = index.internalPointer()
        node = item.node()

        attributeMap = node.attributes()
        attributes = []        
        if index.column() == 0:
            return node.nodeName()
        elif index.column() == 1:
            for i in range(0, len(attributeMap)):
                attribute = attributeMap.item(i)
                attributes.append(str(attribute.nodeName() + "=\""
                                  + attribute.nodeValue() + "\""))
            return "\n".join(attributes)
        elif index.column() == 2:
            return node.nodeValue().split("\n").join(" ")
        return QVariant()

    def flags(self, index):
        if index.isValid():
            return Qt.ItemIsEnabled
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole:
            if section == 0:
                return "name"
            if section == 1:
                return "Attributes"
            if section == 2:
                return "Value"
        return QVariant()

    def index(self, row, column,parent):
        parentItem = None

        if not parent.isValid():
            parentItem = self.rootItem
        else:
            parentItem = parent.internalPointer()
            
        childItem = parentItem.child(row)
        if not childItem is None:
            return self.createIndex(row, column, childItem)
        else:
            return QModelIndex()

    def parent(self, child):
        if not child.isValid():
            return QModelIndex()

        childItem = child.internalPointer()
        parentItem = childItem.parent()

        if not parentItem or parentItem == self.rootItem:
            return QModelIndex()

        return self.createIndex(parentItem.row(), 0, parentItem)

    def rowCount(self, parent):
        parentItem = None
        
        if not parent.isValid():
            parentItem = self.rootItem
        else:
            parentItem = parent.internalPointer()
        return parentItem.node().childNodes().count()

class DomItem():
    def __init__(self, node, row, parent = None):
        self.domNode = node
        self.childItems = {}
        self.rowNumber = row
        self.parentItem = parent

    def node(self):
        return self.domNode

    def parent(self):
        return self.parentItem

    def child(self, i):
        try:
            return self.childItems[i]
        except KeyError:
            pass

        if i >= 0 and i < self.domNode.childNodes().count():
            childNode = self.domNode.childNodes().item(i)
            childItem = DomItem(childNode, i, self)
            self.childItems[i] = childItem
            return childItem
        return 0
    
    def row(self):
        return self.rowNumber

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
#  Jeremy MOUNIER <fba@digital-forensic.org>
import os
from sets import Set

from PyQt4.QtCore import Qt, QSize, SIGNAL, pyqtSignature, QEvent, QCoreApplication, QString
from PyQt4.QtGui import QDockWidget, QWidget, QVBoxLayout, QHBoxLayout, QIcon, QComboBox, QPushButton, QDialog, QWizard, QCursor, QMenu, QListWidget, QAbstractItemView, QListWidgetItem

from dff.api.vfs.libvfs import VFS, ABSOLUTE_ATTR_NAME
from dff.api.types.libtypes import typeId

from dff.ui.gui.resources.ui_attributes_selection_dialog import Ui_AttributesSelectionDialog
from dff.ui.gui.resources.ui_select_attributes import Ui_SelectAttributesWiz

INT_T = [typeId.Int16, typeId.UInt16, typeId.Int32, typeId.UInt16, typeId.Int64, typeId.UInt64]
STRING_T = [typeId.String, typeId.Char, typeId.CArray]
TIME_T = [typeId.DateTime]
BOOL_T = [typeId.Bool]

class AttributeSelectorMenu(QMenu):
  def __init__(self, parent):
     QMenu.__init__(self, parent)
     action = self.addAction(self.tr("Select"))
     self.connect(action, SIGNAL("triggered()"), parent.select) 
     action = self.addAction(self.tr("Unselect"))
     self.connect(action, SIGNAL("triggered()"), parent.unselect) 
     action = self.addAction(self.tr("Select all"))
     self.connect(action, SIGNAL("triggered()"), parent.selectAll) 
     action = self.addAction(self.tr("Unselect all"))
     self.connect(action, SIGNAL("triggered()"), parent.unselectAll) 

class AttributeSelector(QListWidget):
  def __init__(self, name = None, attributes = [], selectedAttributes = []):
     QListWidget.__init__(self)
     self.menu = AttributeSelectorMenu(self)
     self.setSelectionMode(QAbstractItemView.ExtendedSelection)
     if name:
       self.name = name
     self.attributes = attributes
     for attribute in self.attributes:
	item = QListWidgetItem(attribute)
	item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
	if attribute in selectedAttributes:
          item.setCheckState(Qt.Checked)
	else:
	   item.setCheckState(Qt.Unchecked)
	self.addItem(item)

  def selectedAttributes(self):
     selected = []
     for itemId in range(self.count()):
	item = self.item(itemId)
        if item.checkState() != Qt.Unchecked:
	  selected.append(str(item.text().toUtf8()))

     if len(selected):
       return selected
     return None

  def mousePressEvent(self, e):
     index = self.indexAt(e.pos())
     if index.isValid():
       item = self.itemAt(e.pos())
       if e.button() == Qt.RightButton:
	  self.menu.popup(QCursor.pos())
     QListWidget.mousePressEvent(self, e)

  def select(self):
     for item in self.selectedItems():
        item.setCheckState(Qt.Checked)	

  def unselect(self):
     for item in self.selectedItems():
	item.setCheckState(Qt.Unchecked)

  def selectAll(self):
     for itemId in range(self.count()):
	item = self.item(itemId)
        item.setCheckState(Qt.Checked)

  def unselectAll(self):
     for itemId in range(self.count()):
        item = self.item(itemId)
        item.setCheckState(Qt.Unchecked)

class SelectAttributesWizard(QWizard, Ui_SelectAttributesWiz):
    def __init__(self, model, selectedAttributes=None, defaultAttributes = []):
        QWizard.__init__(self)
        self.setupUi(self)
        self.model = model
        self.selectedAttributes = selectedAttributes
	self.defaultAttributes = defaultAttributes
        self.attributes = {}
        self.setOption(QWizard.DisabledBackButtonOnLastPage)
        self.connect(self, SIGNAL("currentIdChanged(int)"), self.idChanged)
        self.connect(self, SIGNAL("updateProgress"), self.updateProgress)
	self.stop = False

    def idChanged(self, pageid):
        if pageid == 0:
            if len(self.model.selection.get()) == 0:
                self.selected.setEnabled(False)
            else:
                self.selected.setEnabled(True)
        elif pageid == 1:
	    nextButton = self.button(QWizard.NextButton)
	    nextButton.setEnabled(False)
            self.progress.setMinimum(0)
            self.progress.setValue(0)
            if self.current.isChecked():
                self.progress.setMaximum(1)
                self.setCurrentAvailableAttributes(self.model.currentNode(), self.attributes)
            elif self.list.isChecked():
		if len(self.model.list()):
                  self.progress.setMaximum(len(self.model.list()))
                  self.setAllAvailableAttributes(self.model.list(), self.attributes)
		else:
	           self.progress.setMaximum(1)
		   self.progress.setValue(1) 
            elif self.selected.isChecked():
                nodes = self.model.selection.getNodes()
                self.progress.setMaximum(len(nodes))
                self.setAllAvailableAttributes(nodes, self.attributes)
	    nextButton.setEnabled(True)
        elif pageid == 2:
            self.tabWidget.clear()
            if self.group_type.isChecked():
                mode = 0
            else:
                mode = 1
            self.generateWidget(self.attributes, mode)

    def updateProgress(self, node):
        self.progress.setValue(self.progress.value() + 1)
        self.currentnode.setText(QString.fromUtf8(node.absolute()))

    def setAllAvailableAttributes(self, nodelist, attributes):
        for node in nodelist:
	    QCoreApplication.processEvents()
            self.setCurrentAvailableAttributes(node, attributes)

    def setCurrentAvailableAttributes(self, node, attributes):
        if node != None:
            attrs = node.attributesNamesAndTypes()
            for attrname, attrtype in attrs.iteritems():
                attributes[attrname] = attrtype
            self.emit(SIGNAL("updateProgress"), node)
	else:
           self.progress.setValue(self.progress.value() + 1)
	

    def attributesByTypes(self, attributes):
        res = {}
        for path, atype in attributes.iteritems():
            if atype not in (typeId.Map, typeId.List):
                try:
                    l = res[self.getTypeName(atype)]
                except KeyError:
                    l = []
                    res[self.getTypeName(atype)] = l
                l.append(path)

        return res

    def getTypeName(self, atype):
        if atype in STRING_T:
            return "String"
        elif atype in INT_T:
            return "Integer"
        elif atype in TIME_T:
            return "Time"
        elif atype in BOOL_T:
            return "Boolean"
        else:
            return "Other"    

    def attributesByModule(self, attributes):
        result = {}
        for attr, atype in attributes.iteritems():
            if atype not in (typeId.Map, typeId.List):
                root = attr.split('.')[0]
                if not root in result:
                    l = []
                    result[root] = l
                else:
                    l = result[root]
                l.append(attr)
        return result

    # 0 : type, 1 : module
    def generateWidget(self, attrs, mode=0):
        if mode == 0:
            attributes = self.attributesByTypes(attrs)
        else:
            attributes = self.attributesByModule(attrs)
	if len(self.defaultAttributes):
  	  widget = AttributeSelector("default", self.defaultAttributes, self.selectedAttributes)
          self.tabWidget.addTab(widget, 'default')
        for modsource, attr_l in attributes.iteritems():
	    attr_l.sort()
            widget = AttributeSelector(modsource, attr_l, self.selectedAttributes) 
            self.tabWidget.addTab(widget, modsource)

    def getSelectedAttributes(self):
        result = []
        for itab in xrange(self.tabWidget.count()):
            listwidget = self.tabWidget.widget(itab)
	    cresult = listwidget.selectedAttributes()
	    if cresult != None:
	      result += cresult
        return result

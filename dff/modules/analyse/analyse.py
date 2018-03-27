# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
# 
from PyQt4.Qt import QHeaderView
from PyQt4.QtCore import SIGNAL, QByteArray, Qt, QObject
from PyQt4.QtGui import QWidget, QHBoxLayout, QTabWidget, QTreeWidget, QTreeWidgetItem, QLabel

from dff.api.vfs.vfs import vfs
from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.filters.libfilters import Filter
from dff.api.module.manager import ModuleProcessusManager

from dff.ui.gui.widget.nodelistwidgets import NodeListWidgets

class Translator(QObject):
  def __init__(self):
    QObject.__init__(self)
    self.translatedMap = self.translationMap()

  def translationMap(self):
     return {}
 
  def translate(self, value):
     if type(value) == list:
       translated = []
       for key in value:
         try:
           translated.append(self.translatedMap[key].encode('UTF-8', 'replace'))
         except KeyError:
           print 'Translation failed word not found ' + key
           translated.append(key)
       return translated
     elif type(value) == tuple:
       translated = ()
       for key in value:
         try:
           translated += (self.translatedMap[key].encode('UTF-8', 'replace'),)
         except KeyError:
           print 'Translation failed word not found ' + key
           translated += (key,)
       return translated
     else:
       try:
         return self.translatedMap[value].encode('UTF-8', 'replace')
       except KeyError: 
         print 'Translation failed word not found ' + value 
         return value

class Analyse(QWidget, Script):
  def __init__(self, name):
     Script.__init__(self, name)
     self.vfs = vfs()
     self.moduleProcessusManager = ModuleProcessusManager()
     self.searchesResults = {}
  
  def g_display(self):
      QWidget.__init__(self)
      self.display()
      if not self.tabWidget.count():
        label = QLabel(self.tr("No results"))
	label.setAlignment(Qt.AlignCenter)
	self.hbox.addWidget(label)
      else:
	self.hbox.addWidget(self.tabWidget)

  def display(self):
     self.initShape()
     self.addSearchesTabs()
     self.stateinfo = "Done"
 
  def searches(self, searchMap, node):
      for key, value in searchMap.iteritems():
         self.stateinfo = "Processing query " + str(value) 
         self.searchesResults[key] = self.searchQuery(value, node)
      self.stateinfo = ""

  def searchQuery(self, query, node):
      filters = Filter("")
      filters.compile(query)
      filters.process(node)
      return filters.matchedNodes()

  def addSearchTab(self, name, nodeList):
     if len(nodeList) > 0:
       browser = NodeListWidgets(self, mode=0)
       browser.model().updateList(nodeList)
       self.tabWidget.addTab(browser, name)

  def initShape(self):
      self.hbox = QHBoxLayout()
      self.hbox.setSpacing(0)
      self.hbox.setContentsMargins(0, 0, 0, 0)
      self.tabWidget = QTabWidget()
      self.setLayout(self.hbox)

  def addSearchesTabs(self):
     for key, value in self.searchesResults.iteritems():
        self.addSearchTab(key, value)       

  def updateWidget(self):
	pass


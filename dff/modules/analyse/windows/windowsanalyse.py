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
from PyQt4 import QtCore
from PyQt4.Qt import Qt, QHeaderView
from PyQt4.QtCore import SIGNAL, QString, QByteArray
from PyQt4.QtGui import QWidget, QHBoxLayout, QVBoxLayout, QTabWidget, QTreeWidget, QTreeWidgetItem, QMessageBox, QTableWidgetItem, QIcon, QSplitter, QLabel, QPushButton, QTextCharFormat, QBrush, QColor

from dff.api.vfs.vfs import vfs
from dff.api.vfs.libvfs import VFS
from dff.api.types.libtypes import MS64DateTime
from dff.api.filters.libfilters import Filter
from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.module.manager import ModuleProcessusManager
from dff.api.report.manager import ReportManager
from dff.api.report.fragments import TableFragment, TabFragment, TextFragment 

from dff.modules.winreg.registrymanager import RegistryManager
from dff.modules.evt.manager import EvtFilteredWidget
from dff.modules.evtx.manager import EvtxFilteredWidget 
from dff.modules.evtx.record import EvtxInfo
from dff.modules.analyse import Analyse

class EvtInfo():
  def __init__(self, record, node, count):
    self.__node = node
    self.__count = count
    self.__record = record

  def node(self):
    return self.__node
  
  def count(self):
    return self.__count

  def record(self):
    return self.__record

class RegistryQueriesParser(object):
  def __init__(self, name, registryMap, root):
     self.registryManager = ModuleProcessusManager().get("winreg")
     self.__queriesSet = {}
     self.__name = name #module name ? 
     self.__root = root
     self.parse(registryMap, root)

  def name(self):
     return self.__name
 
  def root(self):
     return self.__root

  def queriesSet(self, name = None):
     if name == None:
       return self.__queriesSet 
     else:
        try:
          return self.__queriesSet[name]
        except KeyError:
          return None

  def parse(self, registryMap, root):
     for name, queryMap in registryMap.iteritems():
        self.__queriesSet[name] = self.parseQuery(queryMap, root)

  #def report(self, queriesName = None):
     #print "reporting "
     #reportManager = ReportManager()
     #if queriesName == None:
       #page = reportManager.createPage("Analyse", self.__name)
       #queriesTab = TabFragment("")
       #for queryName in self.__queriesSet:
          ##page = reportManager.createPage(self.__name, queryName)
          #tabFragment = TabFragment("")
          #self.__queriesSet[queryName].report(tabFragment)
          #queriesTab.addTab(queryName, tabFragment)
       #page.add(queriesTab)
##XXX overwrite a gerer 
       #reportManager.addPage(page)
     #else:
       ##page = ReportManager.createPage(self.__name, queriesName)
       #page = ReportManager.createPage("Analyse", self.__name)
       #queries = self.__queriesSet[queriesName].report(tabFragment)
##XXX overwrite a gerer
       #reportManager.addPage(page)

  def parseQuery(self, regKeyPath, root):
      regKeys = self.registryManager.getKeys(regKeyPath, root)
      regSplit = regKeys.split()
      
      registryQueries = RegistryQueries()
  
      for node, keys in regSplit.iteritems():
	 for key in keys:
	     try : 
		desc = regKeyPath[key.query]["description"]
	     except (TypeError, KeyError):
                print "query didn't have a description"
		continue
	     try :
		 valueNameDecoder = regKeyPath[key.query]["valuenamedecoder"]
	     except (TypeError, KeyError):
		 valueNameDecoder = None
	     try :
		 valueDataDecoder = regKeyPath[key.query]["valuedatadecoder"]
	     except (TypeError, KeyError):
		 valueDataDecoder = None
	
             query = registryQueries.query(desc, key.path())
             kkey = query.key(key.name)
             kkey.time(node, MS64DateTime(key.mtime))
             values = key.values()
             if values:
               for value in values:
                  if valueNameDecoder:
                    valueName = valueNameDecoder(value.name).decode()
                  else:
                    valueName = value.name #if value.name == None 
                  if valueName:
                    kvalue = kkey.value(valueName)
                    kdatas = []
                    datas = value.data()
                    if type(datas) != list:
                      datas = [datas]
                    for data in datas:
                      if valueDataDecoder:
                        if type(data) == bytearray and len(data):
                          data = valueDataDecoder(data, valueName).decode()
                        elif type(data) == long or type(data) == int:
                          data = valueDataDecoder(data, valueName).decode()
                      kdatas.append(data) 
                    kvalue.data(node, kdatas)  
      return registryQueries

class RegistryQueries(object):
  def __init__(self):
     self.__queries = []

  def report(self, tabFragment):
     print 'reporting queries'
     for query in self.__queries:
        print 'reporting query' + str(query.description())
        tabFragment.addTab(query.description(), query.report())

  def queries(self):
     return self.__queries

  def query(self, description, path):
     for query in self.__queries:
        if query.description() == description:
          return query
     query = RegistryQuery(description, path)
     self.__queries.append(query)
     return query

  def __iter__(self):
     for query in self.__queries:
        yield query

  def __len__(self):
     return len(self.__queries)

  def __getitem__(self, decription):
     for query in self.__queries:
        if description == query.description():
          return query

class RegistryQuery(object):
  def __init__(self, description, path):
    self.__description = description     
    self.__path = path 
    self.__keys = []

  def description(self):
     return self.__description

  def path(self):
     return self.__path 
 
  def keys(self):
     return self.__keys

  def key(self, keyName):
     for key in self.__keys:
        if keyName == key.name():
          return key
     key = RegistryKey(keyName)
     self.__keys.append(key)
     return key   

  def __iter__(self):
     for key in self.__keys:
        yield key

  def __len__(self):
     return len(self.__keys)

  def __getitem__(self, keyName):
     for key in self.__keys:
        if keyName == key.name():
           return key

  def report(self):
     tables = []
     ncount = 0
     nodesHeader = set() 
     for key in self.__keys:
        for node, time in key.times().iteritems():
           nodesHeader.add(node.absolute())        
        nodesHeader = ['key'] + list(nodesHeader)
        rows = []
        for node, time in key.times().iteritems():
           row = []
           for x in range(len(nodesHeader)):
             row.append(None)
           idx = nodesHeader.index(node.absolute())
           row.remove(idx)
           row.insert(idx, time)
        rows.append(row)
        table = TableFragment('', nodesHeader, rows)
        tables.append(table)
     return tables
 
class RegistryKey(object):
  def __init__(self, name):
     self.__name = name
     self.__times = {}
     self.__values = []

  def name(self):
     return self.__name

  def time(self, node, time = None):
     if time:
       self.__times[node] = time
     else:
       return self.__times[node]

  def times(self):
     return self.__times

  def values(self):
     return self.__values

  def value(self, name):
     for value in self.__values:
        if value.name() == name:
           return value
     value = RegistryValue(name)
     self.__values.append(value)
     return value

  def __iter__(self):
     for value in self.__values:
        yield value

  def __len__(self):
     return len(self.__values)

  def __getitem__(self, valueName):
     for value in self.__values:
        if valueName == value.name():
          return value
 
class RegistryValue(object):
  def __init__(self, name):
     self.__name = name
     self.__datas = []

  def name(self):
     return self.__name

  def datas(self):
     return self.__datas

  def data(self, node, data):
     data = RegistryData(node, data) 
     self.__datas.append(data)
     return data

  def __iter__(self):
     for data in self.__datas:
        yield data

  def __len__(self):
     return len(self.__datas)

  def __getitem__(self, dataNode):
    for data in self.__datas:
      if dataNode.uid() == data.node().uid():
        return data

class RegistryData(object):
  def __init__(self, node, datas):
     self.__node = node
     self.__datas = datas

  def datas(self):
     return self.__datas

  def node(self):
     return self.__node

class RegistriesWidget(QWidget):
  def __init__(self, parent, queriesSetName):
    QWidget.__init__(self, parent)
    self.__parent = parent
    self.__name = queriesSetName 
    self.hbox = QVBoxLayout()
    self.treeWidget = RegistriesTreeWidget(self, parent.registryQueriesParser, queriesSetName)
    #buttonReport = QPushButton("&Report", self)
    #self.connect(buttonReport, SIGNAL("clicked()"), self.report)

    self.hbox.addWidget(self.treeWidget)
    #self.hbox.addWidget(buttonReport)
    self.setLayout(self.hbox)

  def report(self):
     self.__parent.registryQueriesParser.report(self.__name)
     #self.treeWidget.report(self.__name, self.__parent.name)

class RegistriesTreeWidget(QTreeWidget):
  def __init__(self, parent, registryQueriesParser, queriesSetName):
    QTreeWidget.__init__(self, parent)
    self.setColumnCount(2)
    self.hLabels = ["Key"]
    self.setHeaderLabels(self.hLabels) 
    self.found = 0
    self.__columnNode = {}
    self.fill(registryQueriesParser.queriesSet(queriesSetName))
    self.header().resizeSections(QHeaderView.ResizeToContents)
    self.header().resizeSections(QHeaderView.Interactive)

  def registryFound(self):
     return self.found

  def dataToQString(self, datas):
     qdatas = []
     for data in datas:
       if type(data) == bytearray:
         data = str(QByteArray(data).toHex())
       elif type(data) == long:
         data = str(data)	  
       elif type(data) == int:
         data = str(data)
       elif data == None:
	 data = 'None'
       else:
         data = data
       qdatas.append(data)
     return QString.fromUtf8(', '.join(qdatas))

  def columnNode(self, node):
     try:
       return self.__columnNode[node.uid()]
     except KeyError:
       column = len(self.__columnNode) + 1
       self.__columnNode[node.uid()] = column
       self.setColumnCount(len(self.__columnNode) + 1)
       self.hLabels.append(node.absolute())
       self.setHeaderLabels(self.hLabels)
       return column

  def fill(self, registryQueries):
    for query in registryQueries:
      queryItem = QTreeWidgetItem(self)
      queryItem.setExpanded(True)
      queryItem.setText(0, QString.fromUtf8(query.path()))
      queryItem.setText(1, QString.fromUtf8(query.description()))

      for key in query:
        keyItem = QTreeWidgetItem(queryItem)
        keyItem.setExpanded(True)
        keyItem.setText(0, QString.fromUtf8(key.name()))
        for node, time in key.times().iteritems():
          keyItem.setText(self.columnNode(node), QString.fromUtf8(str(time)))

        for value in key:
          valueItem = QTreeWidgetItem(keyItem)
          valueItem.setExpanded(True)
          valueItem.setText(0, QString.fromUtf8(value.name()))

          for data in value:
            valueItem.setText(self.columnNode(data.node()), QString.fromUtf8(self.dataToQString(data.datas())))

  def report(self, reportName, parentName):
    reportManager = ReportManager()
    reportManager.createPage(parentName, reportName)

class WindowsAnalyse(Analyse):
  def __init__(self, name):
     Analyse.__init__(self, name)
     try :
       self.registryManager = self.moduleProcessusManager.get("winreg") #XXX manager is not need here 
       self.registryQueriesParser = None
     except :
       self.registryManager = None     
     try:
       self.evtxManager = self.moduleProcessusManager.get('evtx')
     except:
       self.evtxManager = None
     try:
       self.evtManager = self.moduleProcessusManager.get('evt')
     except:
       self.evtManager = None

     self.registryResults = {}
     self.evtResults = {}
     self.evtxResults = {}

  #def report(self):
     #self.registryQueriesParser.report()

#XXX 
     #for widgetID in range(0, self.tabWidget.count()):
        #try:
  	  #self.tabWidget.widget(widgetID).report()
        #except AttributeError:
	   #pass

  def events(self, event_map, root='/'):
    for j in event_map:
      if self.evtxManager and len(self.evtxManager.node_name):
        self.evtx(j, event_map[j])
      if self.evtManager and len(self.evtManager.evts):
        self.evt(j, event_map[j])

  def evtx(self, filter_name, event_map, root='/'):
    records_match = []
    for ptr, chunks in self.evtxManager.getData():
      node = VFS.Get().getNodeById(ptr)
      
      if node.absolute()[:len(root)] != root: continue

      count = 0
      for chunk in self.evtxManager.node_name[long(ptr)]:
        for event in chunk.events():
          match = True
          for f in event_map:
            try:
              if f == 'All' and node.name() == event_map[f]:
                match = True
                break
              match = chunk.events()[event][f] in event_map[f]
            except:
              match = False
            if not match : break
          if match:
            records_match.append(EvtxInfo(event, chunk.events()[event], count, ptr))
        count += 1
    self.evtxResults[filter_name] = records_match

  def evt(self, filter_name, filters, root='/'):
    row = 0
    ignore_bad_filters = False
    records_match = []
    for evt in self.evtManager.evts:
      count = 0
      for record in self.evtManager.evts[evt]:
        for f in filters:
          for i in filters[f]:
            try:
              if f == 'All' or (f == 'id' and i == record.EventID) or (f == 'source' and i == record.sourceName()):
                info = EvtInfo(record, evt, count)
                records_match.append(info)
            except Exception as e:
              continue
        count += 1
    self.evtResults[filter_name] = records_match

  def registries(self, registryMap, root):
      self.registryQueriesParser = RegistryQueriesParser(self.name, registryMap, root)
      #self.registryQueriesParser.parse(registryMap, root)

  def display(self):
     Analyse.display(self)
     self.addRegistryWidget()
     self.addEvtWidgets()
     self.addEvtxWidget()

  def addRegistryWidget(self):
    for queriesSetName, value in self.registryQueriesParser.queriesSet().iteritems():
	 if len(value): 
  	   w = RegistriesWidget(self, queriesSetName)
	   self.tabWidget.addTab(w, queriesSetName) 

  def addEvtxWidget(self):
    for key, value in self.evtxResults.iteritems():
      if len(value):
        w = EvtxFilteredWidget(self, key, value)
	self.tabWidget.addTab(w, key)
 
  def addEvtWidgets(self):
    for key, value in self.evtResults.iteritems():
      if not len(value):
        continue

      w = EvtFilteredWidget(self, key, value)
      self.tabWidget.addTab(w, key)

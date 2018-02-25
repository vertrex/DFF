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
import time, datetime, threading

from PyQt4.QtCore import QString, SIGNAL,Qt, QString 
from PyQt4.QtGui import QWidget, QLabel, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QProgressBar, QMessageBox, QDialog, QTableWidget, QTableWidgetItem, QPushButton, QIcon

from dff.api.taskmanager.taskmanager import TaskManager, ppsched

from dff.pro.api.report.manager import ReportManager
from dff.pro.api.report.fragments import TableFragment, TabFragment, TextFragment

class ReportScan(object):
  def __init__(self, parent):
     self.ppStateWidget = parent
     self.tree = parent.tree
     reportManager = ReportManager()
     page = reportManager.createPage("Information", "Scanner")
     page.addText("Duration" , str(self.ppStateWidget.lastDuration))

     tableHeader = ["Root", "Items",]
     detailTable = page.addDetailTable("Scanner", tableHeader)
     for itemId in xrange(self.tree.topLevelItemCount()):
        item = self.tree.topLevelItem(itemId)
        modulesTable = []
        moduleTableName = ""
        moduleFragment = None
        if item.childCount() <= 1: 
          for childID in xrange(item.childCount()):
             child = item.child(childID)
             moduleTableName = str(child.text(0).toUtf8()) + " (" + str(child.text(1).toUtf8()) + ")"
             if child.childCount() > 0:
               for grandChildID in xrange(child.childCount()):
                  grandChild =  child.child(grandChildID)
                  modulesTable.append([str(grandChild.text(0).toUtf8()),str(grandChild.text(1).toUtf8())])
          if moduleTableName != "":
            moduleFragment = TableFragment(moduleTableName, ["Module", "Count"], modulesTable) 
          row = [str(item.text(0).toUtf8()), str(item.text(1).toUtf8())] 
          detailTable.addRow(row, moduleFragment)
        elif item.childCount() > 1: #Analyse
           analyseTable = []
           for childID in xrange(item.childCount()):
              child = item.child(childID)
              row = [str(child.text(0).toUtf8())]
              analyseTable.append(row)
           page.addTable("Analyse", ["Module"], analyseTable)
     reportManager.addPage(page)


class ModulesTableWidget(QTableWidget):
  def __init__(self, modules):
    QTableWidget.__init__(self)
    self.setColumnCount(2)
    self.setRowCount(len(modules))
    self.setHorizontalHeaderLabels(["Name", "Count"])
    self.horizontalHeader().setStretchLastSection(True)
    self.verticalHeader().hide()
    self.populate(modules)   

  def populate(self, modules):
     i = 0
     for k,v in modules.iteritems():
	item = QTableWidgetItem(str(k))
	item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
	item.setCheckState(Qt.Checked)
	itemv = QTableWidgetItem(str(v))
	itemv.setFlags(Qt.ItemIsEnabled)
        self.setItem(i, 0, item)
        self.setItem(i, 1, itemv)
	i += 1
  
  def state(self):
      modules = []
      for i in xrange(0, self.rowCount()):
	item = self.item(i, 0) 
	if item.checkState() == Qt.Checked:
	  modules.append(str(item.text()))
      return modules

class ModulesMessageBox(QDialog):
   def __init__(self, title, question, modules):
      QDialog.__init__(self)
      button = QPushButton('Ok', self)
      self.modulesTable = ModulesTableWidget(modules)
      layout = QVBoxLayout()
      layout.addWidget(self.modulesTable)
      layout.addWidget(button)
      self.setLayout(layout)
      self.connect(button, SIGNAL("clicked()"), self.accept)
   
   def state(self):
      return self.modulesTable.state()

class PostProcessStateWidget(QWidget):
  def __init__(self, parent = None):
     QWidget.__init__(self, parent)
     self.taskManager = TaskManager()
     self.name = "Scanner"
     self.setWindowIcon(QIcon(":scan"))
     self.state = False
     self.label = QLabel()	
     self.label.setWordWrap(True)
     self.tree = PostProcessJobsTree(self)
     layout = QVBoxLayout()
     layout.setSpacing(0)
     layout.setContentsMargins(0, 0, 0, 0)
     layout.addWidget(self.label)
     layout.addWidget(self.tree) 
     self.setLayout(layout)
     ppsched.registerState(self)
     self.startTime = 0
     self.lastDuration = 0 
     self.connect(self, SIGNAL("sigAskWait"), self.sigAskWait, Qt.BlockingQueuedConnection)
     self.connect(self, SIGNAL("sigAskModulesWait"), self.sigAskModulesWait, Qt.BlockingQueuedConnection)
     self.connect(self, SIGNAL("sigAsk"), self.sigAsk, Qt.BlockingQueuedConnection)

  def sigAskModulesWait(self, title, question, modules):
     m = ModulesMessageBox(title, question, modules)
     m.exec_()
     self.askModulesResult = m.state()

  def askModulesWait(self, title, question, modules):
     self.emit(SIGNAL("sigAskModulesWait"), title, question, modules)
     return self.askModulesResult

  def ask(self, title, question): 
     self.emit(SIGNAL("sigAsk"), title, question)
     return self.askResult

  def askWait(self, title, question): 
     self.emit(SIGNAL("sigAskWait"), title, question)
     return self.askWaitResult

  def sigAsk(self, title, question):
     mbox = QMessageBox(QMessageBox.Warning, self.tr(title), self.tr(question), QMessageBox.Ok, self)
     if mbox.exec_() == QMessageBox.No:
	self.askResult = False
     else:
	self.askResult = True

  def sigAskWait(self, title, question):
     mbox = QMessageBox(QMessageBox.Question, self.tr(title), self.tr(question), QMessageBox.Yes | QMessageBox.No, self)
     if mbox.exec_() == QMessageBox.No:
	self.askWaitResult = False
     else:
	self.askWaitResult = True

  def report(self):
     if self.state == False:
       ReportScan(self)
     else:
       QMessageBox(QMessageBox.Warning, self.tr('Report error'), self.tr("Please wait until the scan is finished."), QMessageBox.NoButton, self).exec_() 	

  def duration(self):
     duration = time.time() - self.startTime
     return str(datetime.timedelta(seconds=duration))

  def updateState(self, state):
     if state == True:
       self.state = True
       self.label.setText("State: Running")
       if self.startTime == 0: 
         self.startTime = time.time()
     else:
       self.lastDuration = self.duration()
       self.label.setText("State: Finished (" + self.duration() + ")" )	
       self.startTime = 0
       self.state = False

class PostProcessJobsTree(QTreeWidget):
  def __init__(self, parent = None):
    QTreeWidget.__init__(self, parent)
    self.taskManager = TaskManager()
    self.setColumnCount(3)
    self.setHeaderLabels(["Root", "Items", "Progress"])   
    self.header().resizeSection(0, 1000) 
    self.jobItemMap = {}
    self.analyseItem = {}
    ppsched.registerDisplay(self)     
    ppsched.processingQueue.registerDisplay(self.rootNodes_s, self.nodeProcessed_s)
    ppsched.processusQueue.registerDisplay(self.setModule_s, self.moduleProcessed_s)
    ppsched.analyseQueue.registerDisplay(self.setAnalyse_s, self.analyseProcessed_s)
    self.connect(self, SIGNAL("rootNodes"), self.rootNodes)
    self.connect(self, SIGNAL("nodeProcessed"), self.nodeProcessed)
    self.connect(self, SIGNAL("setModule"), self.setModule)
    self.connect(self, SIGNAL("moduleProcessed"), self.moduleProcessed)
    self.connect(self, SIGNAL("setAnalyse"), self.setAnalyse)
    self.connect(self, SIGNAL("analyseProcessed"), self.analyseProcessed)
    self.connect(self, SIGNAL("info"), self.info_s)

  def rootNodes_s(self, root, number):
     self.emit(SIGNAL("rootNodes"), root, number)

  def nodeProcessed_s(self, root, count):
     self.emit(SIGNAL("nodeProcessed"), root, count)

  def setModule_s(self, root, moduleCount, modMap):
     self.emit(SIGNAL("setModule"), root, moduleCount, modMap)

  def moduleProcessed_s(self, root, count, module, moduleCount):
     self.emit(SIGNAL("moduleProcessed"), root, count, module, moduleCount)

  def setAnalyse_s(self, root, modCount, modMap):
     self.emit(SIGNAL("setAnalyse"), root, modCount, modMap)

  def analyseProcessed_s(self, root, count, module, moduleCount):
     self.emit(SIGNAL("analyseProcessed"), root, count, module, moduleCount)

  def info(self, root):
     self.emit(SIGNAL("info"), root)
 
  def info_s(self, root):
    try :
      job = self.jobItemMap[root]	
    except KeyError:
      job = JobItem(self, root)
      self.jobItemMap[root] = job
      self.createProgressBar(job)
 
  def createProgressBar(self, item):
      progress = QProgressBar(self)
      self.setItemWidget(item, 2, progress)

  def rootNodes(self, root, number):
     try:
	item = self.jobItemMap[root]
        item.setText(1, str(number))
        self.setRangeProgressBar(item, number)
     except KeyError:
	print "error no item found"
	pass

  def setRangeProgressBar(self, item, number):
     self.itemWidget(item, 2).setRange(0, number)

  def nodeProcessed(self, root, count):
     try:
	item = self.jobItemMap[root]
	self.updateProgressBar(item, count)
     except KeyError:
	print "nodeProcessed : error no item found " + str(root.absolute())
	pass

  def updateProgressBar(self, item, count):
     self.itemWidget(item, 2).setValue(count)

  def moduleProcessed(self, root, count, module, moduleCount):
     try:
	item = self.jobItemMap[root]
	if item.processusItem:
	  processusItem = item.processusItem
	  self.updateProgressBar(processusItem, count)
	  itemModule = processusItem.moduleMap[module] 
	  self.updateProgressBar(itemModule, moduleCount)
     except (KeyError, AttributeError):
        print "moduleProcessed error no item found " + str(root.absolute()) + " " + str(module)
	pass
  
  def expandItemSig(self, item):
     self.expandItem(item)

  def setModule(self, root, moduleCount, modMap):
     try: 
       item = self.jobItemMap[root]
       childItem = moduleItem(item)
       self.expandItemSig(item)
       childItem.setText(0, "Modules")
       childItem.setText(1, str(moduleCount))
       item.processusItem = childItem
       self.createProgressBar(childItem)
       self.setRangeProgressBar(childItem, moduleCount)
       for key, value in modMap.iteritems():
	  grandChildItem = QTreeWidgetItem(childItem)	
	  grandChildItem.setText(0, str(key))
	  grandChildItem.setText(1, str(value))
          self.createProgressBar(grandChildItem)
          self.setRangeProgressBar(grandChildItem, value)
	  childItem.moduleMap[key] = grandChildItem
     except KeyError:
	pass

  def analyseProcessed(self, root, count, module, moduleCount):
       try:
	  item = self.analyseItem[root]
	  self.updateProgressBar(item, count)
	  itemModule = item.moduleMap[module]
	  self.updateProgressBar(itemModule, moduleCount)
       except KeyError:
	pass

  def setAnalyse(self, root, modCount, modMap):
     try:
	childItem = moduleItem(self)
        childItem.setText(0, "Analyse")
	childItem.setText(1, str(modCount))
        self.analyseItem[root] = childItem
        self.createProgressBar(childItem)
        self.setRangeProgressBar(childItem, modCount)
        for key, value in modMap.iteritems():
	   grandChildItem = QTreeWidgetItem(childItem)
	   grandChildItem.setText(0, str(key))
           grandChildItem.setText(1, str(value))
           self.createProgressBar(grandChildItem)
           self.setRangeProgressBar(grandChildItem, value)
	   childItem.moduleMap[key] = grandChildItem
     except KeyError:
	pass

class moduleItem(QTreeWidgetItem):
  def __init__(self, parent):
    QTreeWidgetItem.__init__(self, parent)
    self.moduleMap = {}
     
class JobItem(QTreeWidgetItem):
  def __init__(self, parent, root):
    QTreeWidgetItem.__init__(self, parent)
    self.moduleApplyed = {}
    self.root = root
    self.processCount = 0
    self.processedCount = 0
    self.processusItem = None
    self.setText(0, QString.fromUtf8(self.root.absolute()))

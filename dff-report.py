#!/usr/bin/python
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

"""@package dff
Digital-forensic framework launcher
"""
import os, sys, getopt

#sys.setcheckinterval(1000)

from dff.api.manager.manager import ApiManager

from dff.ui.console.console import Console
from dff.ui.ui import UI


import sys
from dff.api.taskmanager.taskmanager import TaskManager, ppsched
from dff.api.filters.libfilters import Filter
from dff.api.vfs.vfs import vfs
from dff.api.module.manager import ModuleProcessusManager
from dff.api.report.manager import ReportManager
from dff.api.types.libtypes import Variant, Argument, typeId, ConfigManager
import time 

MODULES_PATHS = ["dff/modules", "dff/pro/modules"]
PROCESSING_MODULES =  ['partition', 'ntfs', 'extfs', 'hfsp', 'winreg', 'evtx', 'sqlitedb', 'hash', 'exchange', 'evt', 'lnk', 'compound', 'metaexif',  'prefetch'] #,'skindetection'] #vshadow, #uncompress
PROCESSING_ANALYSES = ['Network','Software', 'System', 'Devices', 'Accounts', 'WebBrowsers', 'Skype', 'Malware Analyse']

class Arguments():
  def __init__(self):
    self.debug = True
    self.verbosity = 1

class ReportUI(UI):
  def __init__(self, arguments):
    UI.__init__(self, arguments)
    self.taskManager = TaskManager()
    self.reportManager = ReportManager()
    self.registryManager = ModuleProcessusManager().get("winreg")
    self.evtxManager = ModuleProcessusManager().get("evtx")
    self.sqliteManager = ModuleProcessusManager().get('SqliteDB')
    self.root = vfs().getnode("/")

  def configureProcessing(self):
    self.taskManager.addPostProcessingModules(PROCESSING_MODULES)
    self.taskManager.addPostProcessingAnalyses(PROCESSING_ANALYSES)
    self.taskManager.addAnalyseDependencies()

  def launchProcessing(self):
    proc = self.taskManager.add("local", {"path": self.dumpPath}, "console")
    proc.event.wait()
    self.taskManager.join() 

  def launch(self):
    self.startTime = time.time()

    self.dumpPath = sys.argv[1]
    self.reportPath = sys.argv[2]

    #PROCESSING 
    self.configureProcessing()
    self.launchProcessing()

    self.searchTaggedNode()
    self.addProcessingTime()

    self.reportManager.setExportPath(self.reportPath)
    self.reportManager.export(exportContent=True)
    
    #SHOW EXECUTION TIME
  def addProcessingTime(self):
    totalTime = time.time() - self.startTime
    if totalTime > 60:
      totalTime = str(totalTime / 60) + " minutes"
    else:
      totalTime = str(totalTime) + " secondes"

    page = self.reportManager.createPage("MyAnalysis", "Stats")
    page.addText("Processing time ",  totalTime)
    self.reportManager.addPage(page)

  def searchTaggedNode(self):
    f = Filter("")
    f.compile('tags in ["malware", "suspicious"]')
    f.process(self.root)
    malwareNodes = f.matchedNodes()
    if len(malwareNodes) != 0: #if get some results we add it to the report
        page = self.reportManager.createPage("MyAnalysis", "Files")
        page.addNodeList("Malware", malwareNodes)
        self.reportManager.addPage(page)

  def searchRegistryKeys(self):
    regKeys = self.registryManager.getKeys({ 'HKLM\Software\Microsoft\Windows NT\CurrentVersion' : ['*']  }, root)
    table = []
    for key in regKeys:
      for value in key.values():
        data = value.data()
        if type(data) != bytearray:
          table.append((value.name, data, key.hive.absolute(),))

    registryPage = iself.reportManager.createPage("MyAnalysis", "Registry")
    registryPage.addTable("Current version", ["name", "value", "hive path"], table)
    self.reportManager.addPage(registryPage)

  def searchSQL(self):
    cookiePage = reportManager.createPage("MyAnalysis", "Cookies")
    for db, node in sqliteManager.databases.iteritems():
      sqltables = db.execute("SELECT * FROM cookies").fetchall()
      table = []
      for row in sqltables:
         table.append((row[1],))
      if len(table):
        cookiePage.addTable(node.absolute(), ["site"], table)  
    reportManager.addPage(cookiePage)

  def searchEVTX(self):
    events = self.evtxManager.getXmlById({"id":[4624]}, "/")
    table = []
    for event in events:
      try:
        etime = event.findall(".//TimeCreated")[0].attrib["SystemTime"]
        user = event.findall(".//Data[@Name='SubjectUserName']")[0].text
        domain = event.findall(".//Data[@Name='SubjectDomainName']")[0].text
        table.append((etime,user,domain,))
      except :
        pass
 
    #NODES COUNT AND STATS (type of files etc ?)
    #save to reload ? :) 
    eventPage = self.reportManager.createPage("MyAnalysis", "Event")
    eventPage.addTable("Login", ["time", "user", "domain"], table)
    self.reportManager.addPage(eventPage) 

if __name__ == "__main__":
    """Take a dump as argument and create a report"""
    ui = ReportUI(Arguments())
    ui.loadModules(MODULES_PATHS)
    ui.launch()
    exit(42)

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

__dff_module_fileinfo_version__ = "1.0.0"

import os

from PyQt4.QtCore import Qt, SIGNAL
from PyQt4.QtGui import QWidget, QVBoxLayout, QTabWidget, QPushButton, QProgressDialog, QListWidget, QListWidgetItem, QFileDialog, QMenu, QCursor, QAction, QAbstractItemView, QProgressDialog

from dff.api.vfs.exportcsv import CSV
from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.types.libtypes import typeId, Argument, Parameter
#from dff.api.taskmanager.scheduler import sched

from dff.ui.gui.dialog.selectattributes import AttributeSelector

class ExportCSV(QWidget, Script): 
  def __init__(self):
     Script.__init__(self, "exportcsv")

  def start(self, args):
     self.outputpath = args["outputpath"].value().path
     try :
       self.split = not args["no split"].value()
     except IndexError:
       self.split = True

     rootArgs = args["root"]
     self.csv = CSV(rootArgs.value()) 

  def updateWidget(self):
     pass

  def g_display(self):
     QWidget.__init__(self)
     self.hlayout = QVBoxLayout()
     self.tabWidget = QTabWidget()	
     default = 'default'
     self.tabWidget.addTab(AttributeSelector(default, self.csv.attributesMap[default]), default)
     for key in self.csv.attributesMap:
	if key != default:
  	  self.tabWidget.addTab(AttributeSelector(key, self.csv.attributesMap[key]), key)
     self.attributesSet = list() 
   
     self.hlayout.addWidget(self.tabWidget)
     self.buttonExport = QPushButton(self.tr("&Export"))
     self.connect(self.buttonExport, SIGNAL("clicked()"), self.export)
     self.hlayout.addWidget(self.buttonExport)
     self.setLayout(self.hlayout)

  def export(self):
     for widgetId in xrange(self.tabWidget.count()):
      attribute = self.tabWidget.widget(widgetId).selectedAttributes()
      if attribute:
	self.attributesSet += attribute

     outputpath = QFileDialog.getSaveFileName(self, self.tr("Choose export path and name of the document."), self.outputpath)
     if outputpath != "":
       self.outputpath = str(outputpath.toUtf8())

        
       taskCreate = (self.createCSV, (self.outputpath, self.split, self.attributeSet, ),) #outputpath, attribues list or will use default
       taskShowExport = (self.showExport, (),)
       self.buttonExport.setEnabled(False)
       sched.enqueue((taskCreate, taskShowExport,))

  def showExport(self):
     self.stateinfo = "CSV exported successfully"
     self.buttonExport.setEnabled(True)

  def c_display(self):
     self.csv.createCSV(self.outputpath, self.split)
     self.stateinfo = "CSV exported successfully"

class exportcsv(Module):
  """Extract all node metadata into externals CSV files.
By default file are split after 65535 row (Excel 2003 format)"""
  def __init__(self):
    Module.__init__(self, "exportcsv",  ExportCSV)
    self.conf.addArgument({"name": "root",
			   "description" : "Root from where the analysis will start",
			   "input" : Argument.Required|Argument.List|typeId.Node,
			   #"parameters" : {"type": Parameter.Editable, 
					   #"predefined" : [vfs().getnode("/")]},
			  })
    self.conf.addArgument({"input": Argument.Required|typeId.Path|Argument.Single,	
			   "parameters" : {"type" : Parameter.Editable, 
					   "predefined" : [os.path.expanduser('~') + "/dff.csv"]},
			   "name" : "outputpath",
			   "description" : "Path where to output csv file."
			  })
    self.conf.addArgument({"name" : "no split",
			   "description" : "Don't split file after 65535 row",
			   "input" : Argument.Empty
			  })
    self.flags = ["console", "gui"]
    self.tags = "Export" 
    self.icon = ":spreadsheet.png"

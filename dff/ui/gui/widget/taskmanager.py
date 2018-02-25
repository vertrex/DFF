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
#  Solal Jacob <sja@digital-forensic.org>
#  Jeremy MOUNIER <jmo@digital-forensic.org>
#
import time
from datetime import datetime
from Queue import Empty

from PyQt4.QtCore import QRect, QSize, Qt, SIGNAL, QEvent
from PyQt4.QtGui import QAction, QApplication, QDockWidget, QIcon,  QHBoxLayout, QPushButton, QTabWidget, QTreeWidget, QTreeWidgetItem, QWidget, QDialog, QGridLayout, QLabel, QComboBox, QVBoxLayout, QHBoxLayout, QDialogButtonBox, QTextEdit

from dff.api.taskmanager.processus import ProcessusManager 

from dff.api.gui.widget.textedit import TextEdit
from dff.api.gui.widget.varianttreewidget import VariantTreeWidget

from dff.ui.gui.resources.ui_taskmanager import Ui_TaskManager

class ProcessusItem(QTreeWidgetItem):
  def __init__(self, parent = None):
     QTreeWidgetItem.__init__(self, parent)
  
  def __lt__(self, cmpitem):
     column = self.treeWidget().sortColumn()
     if column == 0:
	return int(self.text(column)) < int(cmpitem.text(column))
     else:
	return self.text(column)  < cmpitem.text(column)

class Processus(QTreeWidget, Ui_TaskManager):
    def __init__(self, parent):
        super(QTreeWidget, self).__init__()
        self.setupUi(self)
        self.tr("Fail")
        self.tr("Finish")
        self.tr("Running")
        self.__mainWindow = parent        
        self.name = "Task manager"
        self.initTreeProcess()
        self.setSortingEnabled(True)

    def initTreeProcess(self):
 	self.connect(self, SIGNAL("itemDoubleClicked(QTreeWidgetItem*,int)"), self.procClicked)
	self.procItemDic = dict()
        self.procChildItemDic = dict()

    def procClicked(self, item, column):
	dial = procMB(self, self.__mainWindow, item.text(0))
	dial.exec_()

    def LoadInfoProcess(self):
	processusManager = ProcessusManager()
	for proc in processusManager:
	  try:
	    item = self.procItemDic[proc]
	  except KeyError:
	    item = ProcessusItem(self)
	    self.procItemDic[proc] = item
	    item.setText(0, str(proc.pid))
	    item.setText(1, str(proc.name))
          if item.text(2) != self.tr(proc.state):
            item.setText(2, self.tr(proc.state))
          if item.text(3) != str(proc.stateinfo):
	    item.setText(3, str(proc.stateinfo))
	  duration = self.procDuration(proc)
	  item.setText(4, str(duration))

    def procDuration(self, proc): 
	  if proc.timestart:
            stime = datetime.fromtimestamp(proc.timestart)
            if proc.timeend:
  	      etime = datetime.fromtimestamp(proc.timeend)
            else:
	      etime = datetime.fromtimestamp(time.time())
	    delta = etime - stime
	  else:
	    delta = 0
	  return delta
 
    def deleteInfoProcess(self):
        self.clear()

    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
        else:
            QTreeWidget.changeEvent(self, event)


class procMB(QDialog):
    def __init__(self, parent, mainWindow, pid):
        QDialog.__init__(self, parent)
        self.translation()
        self.setWindowTitle(self.nameTitle)
        self.processusManager = ProcessusManager()
        self.pid = pid
        res = {}
        args = {}
        self.tabwidget = QTabWidget(self)
	stream = None
	proc = self.processusManager[int(str(self.pid))]
        res = proc.res
        args = proc.args
	if proc.streamOut == None: 
  	  try :
             proc.streamOut = ''
             txt = proc.stream.get(0)
             proc.streamOut += txt
             while txt:
                  txt = proc.stream.get(0)
                  proc.streamOut += txt
	  except Empty:
		 pass
	  if proc.streamOut and proc.streamOut != '':
	     stream = proc.streamOut
        self.box = QVBoxLayout()
        self.setLayout(self.box)
        self.box.addWidget(self.tabwidget)
        self.dialogButtonsLayout = QHBoxLayout()
        self.dialogButtonsBox = QDialogButtonBox()
        self.dialogButtonsBox.setStandardButtons(QDialogButtonBox.Ok)
        self.connect(self.dialogButtonsBox, SIGNAL("accepted()"), self.accept)
        self.dialogButtonsLayout.addWidget(self.dialogButtonsBox)
        self.setMinimumSize(800, 600)
        if args and len(args) > 0:
            self.treeargs = VariantTreeWidget(self)
            self.treeargs.fillMap(self.treeargs, args)
            self.tabwidget.addTab(self.treeargs, self.argname)
            for i in [0, 1]:
                self.treeargs.resizeColumnToContents(i)
	if stream:
  	   textWidget = TextEdit(proc)
           textWidget.emit(SIGNAL("puttext"), proc.streamOut)
	   self.tabwidget.addTab(textWidget, self.outputname)
        if proc.error_result != '':
	#XXX FIX for swig problem with results, this should not work in console anymore 
	   textWidget = QTextEdit()
	   textWidget.setReadOnly(1)
	   textWidget.append(proc.error_result)
	   self.tabwidget.addTab(textWidget, self.tr('Error'))
        if len(res) > 0:
            self.treeres = VariantTreeWidget(self)
            self.treeres.fillMap(self.treeres, res)
            self.tabwidget.addTab(self.treeres, self.resname)
            for i in [0, 1]:
                self.treeres.resizeColumnToContents(i)
        else:
            label = QLabel(self.noResult)
            label.setAlignment(Qt.AlignCenter)
            self.tabwidget.addTab(label, self.resname)
        self.box.addLayout(self.dialogButtonsLayout)
            

    def translation(self):
        self.outputname = self.tr("Output")
        self.argname = self.tr("Provided Arguments")
        self.resname = self.tr("Results")
        self.nameTitle = self.tr('Processus Information')
        self.noResult = self.tr("No results")

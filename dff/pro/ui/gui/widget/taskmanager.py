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
import time
from datetime import datetime

from dff.api.types.libtypes import Variant, typeId
from dff.api.taskmanager.processus import ProcessusManager 
from dff.api.report.manager import ReportManager
from dff.api.report.fragments import TableFragment, TabFragment, TextFragment

from dff.ui.gui.widget.taskmanager import Processus

class ReportTraceability():
  def __init__(self):
     reportManager = ReportManager()
     page = reportManager.createPage("Information", "Traceability") 
     tableHeader = ["PID", "Name", "State", "Info", "Duration",] 
     detailTable = page.addDetailTable("traceability", tableHeader)
     processusManager = ProcessusManager()
     for proc in processusManager:
       detailTable.addRow(*self.generateRow(proc))
     reportManager.addPage(page)

  def generateRow(self, proc):
     tabFragment = TabFragment("")  
 
     if proc.args and len(proc.args) > 0:   
       argumentTable = []
       for argname in proc.args.keys():
         var = proc.args[argname]
         if var.type() == typeId.List:
           i = 1 
           vlist = var.value()
           for vvar in vlist:
             row = [argname + ' (' + str(i) + ')', str(vvar)]   
             argumentTable.append(row)       
             i += 1 
         else: 
           row = [argname, str(var)]
           argumentTable.append(row)       
       tabFragment.addTab("Arguments", TableFragment("", ["argument", "value"], argumentTable))
 
     if len(proc.res):
       resultTable = []
       self.variantToTable("", Variant(proc.res), resultTable)
       tabFragment.addTab("Result", TableFragment("", ["result", "value"], resultTable))

     if proc.error_result != '':
       tabFragment.addTab("Error", TextFragment("", proc.error_result.replace('\n', '<br>')))
     row = ([str(proc.pid), str(proc.name), str(proc.state), str(proc.stateinfo), str(self.procDuration(proc)),], tabFragment)
     return row

  def variantToTable(self, keypath, var, resultTable):
    if var.type() == typeId.Map:
       vmap = var.value()
       for key, vvar in vmap.iteritems():
          if len(keypath):
            keyabsolute = keypath + "." + str(key)
          else:
            keyabsolute = str(key)
          if not len(keypath):
            resultTable.append([keyabsolute, ""]) 
          self.variantToTable(keyabsolute, vvar, resultTable)
    else:
      resultTable.append([keypath, str(var.value())])

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

class ProcessusPro(Processus):
  def __init__(self, parent):
     Processus.__init__(self, parent)
   
  def report(self):
     ReportTraceability()

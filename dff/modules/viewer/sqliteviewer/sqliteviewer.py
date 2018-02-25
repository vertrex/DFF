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
#  Jeremy MOUNIER <jmo@digital-forensic.org>

__dff_module_sqlitemanager_version__ = "1.0.0"

from PyQt4.QtCore import Qt, QString, SIGNAL
from PyQt4.QtGui import QWidget, QVBoxLayout

from dff.api.types.libtypes import Argument, typeId
from dff.api.taskmanager.taskmanager import TaskManager
from dff.api.module.module import Module 
from dff.api.module.script import Script

from dff.modules.viewer.sqliteviewer.manager import SqliteDatabaseWidget
from dff.modules.databases.sqlite.sqlitedb import SqliteDB

class SQLITEMANAGER(SqliteDatabaseWidget, Script):
  def __init__(self):
    Script.__init__(self, "sqliteviewer")

  def start(self, args):
    try:
      self.node = args["file"].value()
      TaskManager().add("sqlitedb", args,[])
    except Exception as e:
      self.node = None


  def g_display(self):
    if self.node is not None:
      SqliteDatabaseWidget.__init__(self, self.node)
    

  def updateWidget(self):
    pass


  def c_display(self):
    print "Not supported"


class sqliteviewer(Module):
  """SQLite databases viewer"""
  def __init__(self):
    Module.__init__(self, "sqliteviewer", SQLITEMANAGER)
    self.tags = "Viewers"
    self.flags = ["gui"]
    self.icon = ":database"
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node,
                           "name": "file",
                           "description": "sqlite db node."
                          })
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["database/sqlite"]})
    self.conf.addArgument({"name": "preview",
			   "description": "Preview mode",
			   "input": Argument.Empty})

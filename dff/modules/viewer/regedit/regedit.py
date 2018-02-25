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
# 

__dff_module_regedit_version__ = "1.0.0"

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import Qt, SIGNAL
from PyQt4.QtGui import QWidget, QVBoxLayout, QTreeView, QSplitter

from dff.api.vfs.vfs import vfs
from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.types.libtypes import Variant, VList, VMap, Argument, Parameter, typeId

from dff.modules.regedit.model.regtree import RegTreeModel
from dff.modules.regedit.view.regtreeview import RegTreeView
from dff.modules.regedit.view.valueview import TableValue
from dff.modules.regedit.view.keyinfoview import KeyInfoView


class REGEDIT(QWidget, Script):
  def __init__(self):
    Script.__init__(self, "Registry viewer")
    self.name = "Registry viewer"
    self.vfs = vfs()
    self.icon = None
  
  def start(self, args):
    self.args = args
    try:
      self.mountpoints = args["mountpoints"].value()
    except:
      print "No mount points"
      pass

  def g_display(self):
    QWidget.__init__(self, None)
    vlayout = QVBoxLayout()
    splitter = QSplitter(Qt.Horizontal)
    treemodel = RegTreeModel(self)
    treeview = RegTreeView(self)
    keyinfo = KeyInfoView(self, treemodel)
    tablevalue = TableValue(treemodel, self)
    treeview.setModel(treemodel)
    splitter.addWidget(treeview)
    splitter.addWidget(tablevalue)
    vlayout.addWidget(splitter)
    vlayout.addWidget(keyinfo)
    self.setLayout(vlayout)
#    self.regv = regviewer(self, self.mountpoints)

  def updateWidget(self):
	pass

class regedit(Module):
  """Windows registry viewer"""
  def __init__(self):
    Module.__init__(self, "Registry viewer", REGEDIT)
    self.conf.addArgument({"input": Argument.Optional|Argument.List|typeId.Node,
                           "name": "mountpoints",
                           "description": "mountpoints of (NTFS) file systems",
                           "parameters": {"type": Parameter.Editable,
                                          "minimum": 1}
                           })
    self.tags = "Viewers"
    self.flags = ["gui"]
    self.icon = ":text"	

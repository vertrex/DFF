# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
#
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
#  Jeremy Mounier <jmo@digital-forensic.org>
#

__dff_module_hexeditor_version__ = "1.0.0"

import sys

from PyQt4.QtCore import QSize, SIGNAL
from PyQt4.QtGui import QWidget, QVBoxLayout, QIcon, QMessageBox

from dff.api.module.script import Script
from dff.api.module.module import Module
from dff.api.types.libtypes import Argument, typeId

from dff.ui.gui.utils.utils import Utils

from Heditor import Heditor

try :
  import nceditor
except ImportError:
  pass

class ViewerHexa(QWidget, Script):
    def __init__(self):
        Script.__init__(self, "hexedit")
        self.type = "hexedit"
#        self.icon = ":hexedit.png"
        
    def start(self, args) :
        self.node = args["file"].value()
	try:
   	  self.preview = args["preview"].value()
	except IndexError:
          self.preview = False

    def c_display(self):
	try:
          nceditor.start(self.node)
	except NameError:
	  print "This functionality is not available on your operating system"	

    def g_display(self):
        QWidget.__init__(self)
        self.widget = Heditor(self)
        self.name = "hexedit " + str(self.node.name())
        if self.node.size() > 0:
          self.widget.init(self.node, self.preview)
          self.setLayout(self.widget.vlayout)
        else:
          msg = QMessageBox(QMessageBox.Critical, "Hexadecimal viewer", "Error: File is empty", QMessageBox.Ok)
          msg.exec_()
          
    def closeEvent(self, event):
      self.widget.close()
 
    def updateWidget(self):
        pass

    def initCallback(self):
        pass 
    
    def refresh(self):
        pass 

class hexeditor(Module):
  """Displays content of a file as an hexadecimal view"""
  def __init__(self):
    Module.__init__(self, "hexadecimal", ViewerHexa)
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                           "name": "file",
                           "description": "Files to display as hexadecimal"})
    self.conf.addArgument({"name": "preview",
			   "description": "Preview mode",
			   "input": Argument.Empty})
    self.tags = "Viewers"
    self.icon = ":hexedit.png"


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
#  Frederic B. <fba@digital-forensic.org>

__dff_module_carvergui_version__ = "1.0.0"

from PyQt4.QtGui import QWidget, QVBoxLayout, QGridLayout, QLabel, QProgressBar, QHBoxLayout, QTabWidget
from PyQt4.Qt import SIGNAL


from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.types.libtypes import typeId, Argument, Parameter

from dff.modules.carver.predef import PredefinedPatterns
from dff.modules.carver.userdef import UserPatterns

class CarverGui(QWidget, Script):
    def __init__(self):
        Script.__init__(self, "carver-gui")


    def start(self, args):
        self.args = args
        self.node = args["file"].value()
        self.name += " <" + self.node.name() + ">"
        self.filesize = self.node.size()


    def status(self):
        return 0


    def g_display(self):
        #define layout
        QWidget.__init__(self)
        self.baseLayout = QHBoxLayout()
        self.setLayout(self.baseLayout)
        self.tabwidgets = QTabWidget()

        #define all area
        self.user = UserPatterns(self.args["file"])
        self.pp = PredefinedPatterns(self.args["file"])
        self.tabwidgets.addTab(self.pp, "Predefined Patterns")
        self.tabwidgets.addTab(self.user, "User defined")
        #add widget and hide progress bars
        self.baseLayout.addWidget(self.tabwidgets)
        

    def updateWidget(self):
        pass


    def setStateInfo(self, sinfo):
        self.stateinfo = str(sinfo)


class carvergui(Module):
  """Search for header and footer of a selected mime-type in a node and create the corresponding file.
You can use this modules for finding deleted data or data in slack space or in an unknown file system."""
  def __init__(self):
    Module.__init__(self, 'carvergui', CarverGui)
    self.conf.addArgument({"name": "file",
                           "input": typeId.Node|Argument.Single|Argument.Required,
                           "description": "Node to search data in"})
    self.tags = "Search"

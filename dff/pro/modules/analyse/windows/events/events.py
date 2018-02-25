# DFF -- An Open Source Digital Forensics Framework
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
#  Romain BERTHOLON < rbe@digital-forensic.fr>
#

from PyQt4 import QtCore, QtGui
from PyQt4.QtGui import QWidget, QHBoxLayout, QTabWidget, QTableWidgetItem, QIcon, QPixmap, QListWidget, QSplitter, QListWidgetItem

from dff.api.vfs.vfs import vfs 
from dff.api.types.libtypes import Argument, typeId
from dff.api.module.module import Module
from dff.api.module.manager import ModuleProcessusManager

from dff.modules.analyse import Analyse

class WIN_EVENTS(Analyse):
    def __init__(self):
        Analyse.__init__(self, "Windows logs")
        self.__chunk = {}
        self.node = None
        self.name = "Event logs"
        self.viewer = []
        self.w = None
        self.vfs = vfs()

    def start(self, args):
        root = None
        try:
            root = args["root"].value()
        except IndexError:
            root = self.vfs.getnode("/")

    def g_display(self):
         QWidget.__init__(self)
	 self.evtWidget = None
	 self.evtxWidget = None
         layout = QHBoxLayout(self)
	 layout.setSpacing(0)
	 layout.setContentsMargins(0, 0, 0, 0)
         widget = QTabWidget()
         layout.addWidget(widget)

         processus_manager = ModuleProcessusManager()
         evtx = processus_manager.get('evtx')
         evt = processus_manager.get('evt')

         try:
	   self.evtxWidgets = evtx.getall('/')
	   if self.evtxWidgets:
             if self.evtxWidgets.list_widget.count():
               widget.addTab(self.evtxWidgets, "Events logs (.evtx)")
         except Exception as e:
           pass

         try:
	   self.evtWidgets = evt.getAllEvtFiles('/')
	   if self.evtWidgets.evtFileListWidget.count(): 
             widget.addTab(self.evtWidgets, "Events logs (.evt)")
         except Exception as e:
	   pass

    #def report(self):
       #reportManager = ReportManager()  
       #if self.evtxWidgets:
         #self.evtxWidgets.report() 
       #if self.evtWidgets:
	 #self.evtWidgets.report()

    def updateWidget(self):
        pass

class events(Module):
    """
    Display events log of windows
    """
    def __init__(self):
        Module.__init__(self, "Windows logs", WIN_EVENTS)
        self.conf.addArgument({"name": "root",
                               "description" : "Root from where the analysis will start",
                               "input" : Argument.Required|Argument.Single|typeId.Node})
        self.depends = ["File systems", "partition", "evtx", "evt", "ntfs", "vmware"]
        self.tags = "Windows Analyse"
        self.icon = ":toggle_log"

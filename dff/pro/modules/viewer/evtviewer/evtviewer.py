# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
#  Romain Bertholon <rbe@digital-forensic.org>
#

__dff_module_evt_version__ = "1.0.0"

import sys

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import Qt
from PyQt4.QtGui import QWidget, QHBoxLayout, QSplitter

from dff.api.module.script import Script
from dff.api.module.module import Module
from dff.api.module.manager import ModuleProcessusManager
from dff.api.types.libtypes import Argument, typeId

from dff.modules.evt.evt import EVT
from dff.modules.evt.manager import EvtControlPannel

class EvtViewer(QWidget, Script):
    def __init__(self):
        Script.__init__(self, "EvtViewer")
        self.type = "EvtViewer"
        self.t = None
 
    def start(self, args):
        try:
            self.preview = args['preview'].value()
	except IndexError:
            self.preview = False

        try:
            self.node = args['file'].value()
        except (KeyError, Exception):
            print "No input file provided. Exiting."

        t = EVT()
        t.start(args)
        processus_manager = ModuleProcessusManager()
        evt = processus_manager.get('evt')
        evt.update(t)

    def updateWidget(self):
        pass

    def g_display(self):
        QWidget.__init__(self)

        layout = QHBoxLayout(self)
        splitter = QSplitter()

        layout.addWidget(splitter)
        splitter.setOrientation(Qt.Horizontal)
        
        if self.node is not None:
          processus_manager = ModuleProcessusManager()
          evt = processus_manager.get('evt')
	  if not self.preview:
            self.evtWidget = evt.getAllEvtFiles()
            if self.evtWidget:
              splitter.addWidget(self.evtWidget)
              splitter.setStretchFactor(1, 2)
	  else:
	    self.evtWidget = evt.previewWidget(long(self.node.this))
            if self.evtWidget:
	      splitter.addWidget(self.evtWidget) 

    #def report(self):
       #self.evtWidget.report() 

class evtviewer(Module):
    """Displays Windows event logs"""
    def __init__(self):
        Module.__init__(self, "evtviewer", EvtViewer)
        self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                               "name": "file",
                               "description": "Events"})
        self.conf.addConstant({"name": "extension-type",
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["Evt", "evt"]})
        self.conf.addArgument({"name": "preview",
                               "description": "Preview mode",
                               "input": Argument.Empty})
        self.depends = ['evt']
        self.tags = "Viewers"

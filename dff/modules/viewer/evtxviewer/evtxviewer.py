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

__dff_module_evt_viewer_version__ = "1.0.0"

from xml.etree.ElementTree import dump, tostring

from PyQt4.QtCore import QSize, SIGNAL, Qt
from PyQt4.QtGui import QWidget, QVBoxLayout, QIcon, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView, QPixmap, QAbstractItemView, QDialog, QSplitter, QPushButton, QSpacerItem, QComboBox, QLabel, QLineEdit, QDateTimeEdit, QListWidget, QListWidgetItem, QHBoxLayout, QTextEdit

from dff.api.types.libtypes import Argument, typeId
from dff.api.module.script import Script
from dff.api.module.module import Module
from dff.api.module.manager import ModuleProcessusManager

#from dff.api.report.document import ReportManager XXX REPORT

from dff.modules.evtx.evtx import EVTX
#from dff.modules.evtx.manager import EvtxDocument
from dff.modules.evtxviewer.evtxviewertree import EvtxTree 
from dff.modules.evtxviewer.evtxviewerpanel import EventLogViewer

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

        self.t = EVTX()
        if not self.preview:
            self.t.start(args)
            processus_manager = ModuleProcessusManager()
            evtx = processus_manager.get('evtx')
            evtx.update(self.t)

    def updateWidget(self):
        pass

    def initCallback(self):
        pass

    def refresh(self):
        pass

    def c_display(self):
        print "cannot display in console mode. You must use the gui"

    def g_display(self):
        QWidget.__init__(self)
        self.layout = QVBoxLayout(self)

        processus_manager = ModuleProcessusManager()
        evtx = processus_manager.get('evtx')

        if not self.preview:
            self.viewer = EventLogViewer(self.node, evtx.data(self.node.uid()))
            self.layout.addWidget(self.viewer)
            self.name = self.node.name()
            self.viewer.display(evtx.data(self.node.uid()), self.node)
        else:            
            self.build_preview()

    #def report(self):
        #reportManager = ReportManager()
        #events = self.viewer.evtx_table_view.selectedEvents()
        #if events and len(events):
          #doc = EvtxDocument(events, str(self.node.name()), 'Case/Events')
          #reportManager.addReportDocument(doc)

    def build_preview(self):
        data = self.t.light_parser(self.node)
        
        self.layout.addWidget(QLabel("File name : " + data['File']))

        tmp_widget = QWidget()
        tmp_layout = QHBoxLayout(tmp_widget)
        
        tmp_layout.addWidget(QLabel("Oldest chunk : " + data['Oldest']))
        tmp_layout.addWidget(QLabel("Current chunk : " + data['Current']))
        tmp_layout.addWidget(QLabel("Next record : " + data['Next']))
        tmp_layout.addWidget(QLabel("Version : " + data['Maj'] + "." + data['Min']))
        tmp_layout.addWidget(QLabel("Chunk number : " + data['chunk_nb']))
        self.layout.addWidget(tmp_widget)
        
        data_list = QTableWidget()
        data_list.setColumnCount(4)

        data_list.setHorizontalHeaderLabels(['Chunk number', 'First record', 'Last record', 'Offset'])
        data_list.horizontalHeader().setStretchLastSection(True)
        data_list.verticalHeader().hide()
        data_list.setSortingEnabled(False)
        data_list.setSelectionBehavior(QAbstractItemView.SelectRows)
        data_list.setEditTriggers(QAbstractItemView.NoEditTriggers)

        data_list.setRowCount(int(data['chunk_nb']))
        for chunk_count in range(int(data['chunk_nb'])):
            rec = data[str(chunk_count)]

            data_list.setItem(chunk_count, 0, QTableWidgetItem(str(chunk_count)))
            data_list.setItem(chunk_count, 1, QTableWidgetItem(rec[0]))
            data_list.setItem(chunk_count, 2, QTableWidgetItem(rec[1]))
            data_list.setItem(chunk_count, 3, QTableWidgetItem(rec[2]))

        self.layout.addWidget(data_list)

    def closeEvent(self, event):
        pass

class evtxviewer(Module):
    """Displays Windows vista,7,8 event logs (evtx)"""
    def __init__(self):
        Module.__init__(self, "evtxviewer", EvtViewer)
        self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                               "name": "file",
                               "description": "Events"})
        self.conf.addConstant({"name": "mime-type",
                               "type": typeId.String,
                               "description": "managed mime type",
                               "values": ["MS Windows Vista Event Log"]})
        self.conf.addArgument({"name": "preview",
                               "description": "Preview mode",
                               "input": Argument.Empty})
        self.depends = ['evtx']
        self.tags = "Viewers"
        

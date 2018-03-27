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

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

from dff.api.vfs.libvfs import VFS

from dff.ui.gui.view.node_list import NodeListView, TimeLineNodeListView
from dff.ui.gui.view.node_table import NodeTableView, TimeLineNodeTableView
from dff.ui.gui.model.node_list import NodeListModel, TimeLineNodeListModel

from dff.ui.gui.model.status import ViewStatusModel, NodeStatusModel, TimeLineNodeViewStatusModel
from dff.ui.gui.widget.status import StatusWidget, StatusBarWidget
from dff.ui.gui.widget.linklabel import LinkLabel

from dff.ui.gui.utils.menumanager import MenuManager
from dff.ui.gui.resources.ui_filter_mode import Ui_filterMode

TABLEVIEW_ID = 0
LISTVIEW_ID = 1

class NodeWidget(QWidget):
    """
    This Widget provide a list model with various view
    """
    def __init__(self, selectionManager, tabmode=False, filtermode=False):
        QWidget.__init__(self)
        self.tabmode = tabmode
        self.filtermode = filtermode
        # setup model and views
        self.viewid = TABLEVIEW_ID
        self.setModel(selectionManager)
        self.__statuswidget = StatusBarWidget()
        QApplication.instance().mainWindow.status.addWidget(self.__statuswidget)
        self.__viewstatus = StatusWidget()
        self.viewStatusSetStatusModel(selectionManager)
        self.__linklabel = LinkLabel()
        self.__nodestatus = StatusWidget()
        self.__nodestatus.setStatusModel(NodeStatusModel(self))
        self.setStatusWidget()
        self.setListView()
        self.setTableView()
        self.tableview.setModel(self.model)
        self.tableview.setColumnWidth(0, 180)
        self.listview.setModel(self.model)
        # Keep track of model list in case of filtering
        self.initialist = []
        # setup graphic stuff
        self.createMainLayout()
        self.createViewLayout()
        self.createStack()
        self.createScrollbar()
        self.createConnections()
        self.menuManager(selectionManager)
        self.connect(self.model, SIGNAL("dataChanged"), self.dataChanged)

    def setStatusWidget(self):
      self.__statuswidget.addStatusWidget(self.__viewstatus, 20)
      self.__statuswidget.addStatusWidget(self.__linklabel, 60)
      self.__statuswidget.addStatusWidget(self.__nodestatus, 20)

    def linkLabel(self):
       return self.__linklabel

    def statusWidget(self):
       return self.__statuswidget

    def nodeStatus(self):
       return self.__nodestatus
 
    def viewStatusSetStatusModel(self, selectionmanager):
        self.__viewstatus.setStatusModel(ViewStatusModel(self.model, selectionmanager))

    def viewStatus(self):
       return self.__viewstatus

    def setListView(self):
        self.listview = NodeListView(self)

    def setTableView(self):
        self.tableview = NodeTableView(self)

    def setModel(self, selectionManager):
        self.model = NodeListModel(selectionManager)

    def updateStatus(self):
        visible = True
        node = self.model.currentNode() if self.model.currentNode() is not None else self.model.currentRoot()
        if node is not None:
          self.__linklabel.setLink(node)
          self.emit(SIGNAL("currentNode"), node)
        else:
          visible = False
        self.__statuswidget.setVisible(visible)
        QApplication.instance().mainWindow.status.setCurrentWidget(self.__statuswidget)

    def statusWidget(self):
        return self.__statuswidget

    def menuManager(self, selectionManager):
        self.menumanager = MenuManager(selectionManager, self.model)

    def refreshIconSize(self, factor):
        self.tableview.factor = factor
        self.tableview.configure()
        self.listview.factor = factor
        self.listview.configure()
        self.refreshVisible()

    def dataChanged(self, x, y):
        self.viewstack.currentWidget().dataChanged(x, y)

    def createMainLayout(self):
        self.vlayout = QVBoxLayout(self)
        self.vlayout.setSpacing(0)
        self.vlayout.setMargin(0)

    def createViewLayout(self):
        container = QWidget()
        self.hlayout = QHBoxLayout()
        self.hlayout.setSpacing(0)
        self.hlayout.setMargin(0)
        container.setLayout(self.hlayout)
        self.vlayout.addWidget(container)

    def createStack(self):
        self.viewstack = QStackedWidget()
        self.viewstack.addWidget(self.tableview)
        self.viewstack.addWidget(self.listview)
        self.hlayout.addWidget(self.viewstack, 99)

    def createScrollbar(self):
        self.scrollbar = ScrollBar(self)
        self.hlayout.addWidget(self.scrollbar, 1)
        self.scrollbar.lower()

    def refreshVisible(self):
        view = self.viewstack.currentWidget()
        view.refreshVisible()

    def createConnections(self):
        self.connect(self, SIGNAL("changeView"), self.changeView)
        self.connect(self.tableview, SIGNAL("nodeListClicked"), self.nodelistclicked)
        self.connect(self.tableview, SIGNAL("nodeListDoubleClicked"), self.nodelistDoubleclicked)
        self.connect(self.model, SIGNAL("nodeListClicked"), self.nodelistclicked)
        self.connect(self.tableview, SIGNAL("enterDirectory"), self.enterDirectory)
        self.connect(self.listview, SIGNAL("enterDirectory"), self.enterDirectory)
        self.connect(self.listview, SIGNAL("nodeListClicked"), self.nodelistclicked)
        self.connect(self.listview, SIGNAL("nodeListDoubleClicked"), self.nodelistDoubleclicked)
        self.connect(self.model, SIGNAL("nodeAppended"), self.refreshVisible)

    def enterDirectory(self, sourcenode):
        if sourcenode != None:
            if (not self.tabmode) and (not self.filtermode):
                self.model.changeList(sourcenode)
                self.emit(SIGNAL("pathChanged"), sourcenode)
                if len(self.model.list()) > 0:
                    self.nodelistclicked(0)
            if self.filtermode:
                self.model.clearList()
                self.emit(SIGNAL("enterFilter"), sourcenode)
            if self.tabmode:
                self.openAsNewTab(sourcenode)                
        self.refreshVisible()

    def nodelistclicked(self, button):
        if button == Qt.RightButton:
            self.menumanager.createMenu()
        else:
            node = self.model.currentNode()
            self.emit(SIGNAL("nodePressed"), node)

    def nodelistDoubleclicked(self, node):
        self.menumanager.openDefault(node)

    def changeView(self, index):
        self.viewid = index
        if index == TABLEVIEW_ID:
            self.menumanager.setIconView(False)
            self.viewstack.setCurrentWidget(self.tableview)
            self.model.refresh(self.model.currentRow())
            self.scrollbar.setMaximum(self.scrollbar.value() - 2)
        elif index == LISTVIEW_ID:
            self.menumanager.setIconView(True)
            self.viewstack.setCurrentWidget(self.listview)
            self.model.refresh(self.model.currentRow())
            self.scrollbar.setMaximum(self.scrollbar.value() + 2)
        self.refreshVisible()

    def openAsNewTab(self, rootnode):
        QApplication.instance().mainWindow.addNodeBrowser(rootpath=rootnode)

class TimeLineNodeWidget(NodeWidget):
  def __init__(self, selectionManager, tabmode=False, filtermode=False):
    NodeWidget.__init__(self, selectionManager, tabmode, filtermode)

  def viewStatusSetStatusModel(self, selectionManager):
    self.viewStatus().setStatusModel(TimeLineNodeViewStatusModel(self.model, selectionManager))

  def setModel(self, selectionManager):
    self.model = TimeLineNodeListModel(selectionManager)

  def setListView(self):
     self.listview = TimeLineNodeListView(self)

  def setTableView(self):
     self.tableview = TimeLineNodeTableView(self)

  def updateStatusShowProgressBar(self):
     self.viewStatus().hide()
     self.linkLabel().hide()    
     self.nodeStatus().hide()
     self.progressBar.show()

  def updateStatusShowWidgets(self):
     self.progressBar.hide()
     self.viewStatus().show()
     self.linkLabel().show()
     self.nodeStatus().show()
     self.statusWidget().setVisible(True)
     QApplication.instance().mainWindow.status.setCurrentWidget(self.statusWidget())

  def updateStatusProgressBar(self, processed, toProcess):
     self.progressBar.setRange(0, toProcess)
     self.progressBar.setValue(processed)
     self.statusWidget().setVisible(True)
     QApplication.instance().mainWindow.status.setCurrentWidget(self.statusWidget())

  def updateStatus(self):
     visible = True
     timelineNode = self.model.currentNode()
     if timelineNode is not None:
       node = timelineNode.node()
       if node is not None:
         self.linkLabel().setLink(node)
         self.emit(SIGNAL("currentNode"), node)
     else:
       visible = False
     self.statusWidget().setVisible(visible)
     QApplication.instance().mainWindow.status.setCurrentWidget(self.statusWidget())

  def setStatusWidget(self):
     self.statusWidget().addStatusWidget(self.viewStatus(), 20)
     self.statusWidget().addStatusWidget(self.linkLabel(), 60)
     self.statusWidget().addStatusWidget(self.nodeStatus(), 20)
     self.progressBar = QProgressBar()
     self.progressBar.hide()
     self.statusWidget().addStatusWidget(self.progressBar, 100)

class ScrollBar(QScrollBar):
    def __init__(self, nodeview):
        QScrollBar.__init__(self, nodeview)
        self.model = nodeview.model
        self.nodeview = nodeview
        self.setMinimum(0)
        self.setMaximum(0)
        self.setVisible(False)
        self.connect(self, SIGNAL("sliderMoved(int)"), self.moveTo)
        self.connect(self, SIGNAL("actionTriggered(int)"), self.triggered)
        # Model signals
        self.connect(self.model, SIGNAL("maximum"), self.updateMaximum)
        self.connect(self.model, SIGNAL("hideScroll"), self.hideScrollbar)
        self.connect(self.model, SIGNAL("current"), self.updateCurrent)
        self.nodeview.hlayout.addWidget(self, 1)

    def hideScrollbar(self):
        self.setMinimum(0)
        self.setMaximum(0)
        self.setVisible(False)

    def updateMaximum(self, stop):
        if stop <= self.model.visibleRows():
           self.setMinimum(0)
           self.setMaximum(0)
           self.setVisible(False)
        else:
            m = stop - self.model.visibleRows()
            self.setMaximum(m)
            self.setSingleStep(1)
            self.setVisible(True)

    def updateCurrent(self, current):
        if current >= 0:
            self.setValue(current)

    def triggered(self, action):
        if self.nodeview.viewid == TABLEVIEW_ID:
            f = 1
        else:
            f = self.nodeview.listview.cols
        if action  == QAbstractSlider.SliderSingleStepAdd:
            self.model.seek(self.value() + f)
        elif action == QAbstractSlider.SliderPageStepAdd:
            self.model.seek(self.value() + self.model.visibleRows() - f)
        elif action == QAbstractSlider.SliderSingleStepSub:
            self.model.seek(self.value() - f)
        elif action ==  QAbstractSlider.SliderPageStepSub:
            self.model.seek(self.value() - self.model.visibleRows() - f)
        else:
            return

    def moveTo(self, value):
        self.model.seek(value)


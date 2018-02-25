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
#  Solal Jacob <sja@arxsys.fr>
#
 
from PyQt4.QtCore import SIGNAL, QString
from PyQt4.QtGui import QAction, QIcon, QApplication, QPixmap

from dff.api.gui.widget.nodelistwidgets import NodeListWidgets, ADVANCED

from dff.ui.gui.resources.ui_browser_toolbar import Ui_BrowserToolBar

from dff.pro.ui.gui.widget.nodewidget import NodeWidgetPro
from dff.pro.ui.gui.utils.menumanager import ReportNodesAction 

class NodeListWidgetsPro(NodeListWidgets):
  def __init__(self, parent = None, mode = ADVANCED):
     NodeListWidgets.__init__(self, parent, mode)

  def createNodeWidget(self, selection, tabmode=False, filtermode=False):
     return NodeWidgetPro(selection, tabmode, filtermode)

  def createToolbar(self):
     NodeListWidgets.createToolbar(self)
     self.toolbar.insertAction(self.actionBookmark, self.actionReport)
     self.connect(self.actionReport, SIGNAL("triggered()"), self.reportNodes)

  def reportNodes(self):
    ReportNodesAction(self.model())

  def setupUi(self, BrowserToolBar):
     self.actionReport = QAction(self)
     icon = QIcon()
     icon.addPixmap(QPixmap(QString.fromUtf8(":/report")), QIcon.Normal, QIcon.Off)
     self.actionReport.setIcon(icon)
     self.actionReport.setObjectName(QString.fromUtf8("actionReport"))
 
     Ui_BrowserToolBar.setupUi(self, BrowserToolBar)   

  def retranslateUi(self, BrowserToolBar):
     Ui_BrowserToolBar.retranslateUi(self, BrowserToolBar)
     self.actionReport.setText(QApplication.translate("BrowserToolBar", "report", None, QApplication.UnicodeUTF8))
     self.actionReport.setToolTip(QApplication.translate("BrowserToolBar", "Add nodes to report", None, QApplication.UnicodeUTF8))

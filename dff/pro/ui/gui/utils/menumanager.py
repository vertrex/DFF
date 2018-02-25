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
from PyQt4.QtGui import QIcon, QPixmap, QAction, QApplication, QWidget, QInputDialog, QLineEdit, QWidget, QMessageBox, QDialog

from dff.ui.gui.resources.ui_nodeactions import Ui_nodeActions
from dff.ui.gui.utils.menumanager import MenuManager

from dff.pro.api.report.manager import ReportManager

from dff.pro.ui.gui.widget.reportselect import ReportSelectDialog
from dff.pro.ui.gui.wizard.autowizard import AutoWizard

class ReportNodesAction(QWidget):
  def __init__(self, model):
     QWidget.__init__(self)
     nodes = model.selection.getNodes()
     if len(nodes):
       reportSelectDialog = ReportSelectDialog()
       if reportSelectDialog.exec_() == QDialog.Accepted:
         page = reportSelectDialog.selection()
         if page: 
           page.addNodeList("", nodes)
     else:
        QMessageBox(QMessageBox.Warning, self.tr("Report nodes"), self.tr("No nodes selected")).exec_()

class MenuManagerPro(MenuManager):
  def __init__(self, selection, listmodel):
     MenuManager.__init__(self, selection, listmodel)

  def createMenu(self):
     MenuManager.createMenu(self)
     self.mainmenu.insertSeparator(self.actionOpen_parent_folder)
     self.mainmenu.insertAction(self.actionOpen_parent_folder, self.actionScan)
     self.mainmenu.addSeparator()
     self.mainmenu.insertAction(self.bookseparator, self.actionReport_node)

  def createActions(self):
     MenuManager.createActions(self)
     self.connect(self.actionScan, SIGNAL('triggered()'), self.scan)
     self.connect(self.actionReport_node, SIGNAL('triggered()'), self.reportNode)

  def scan(self):
    autoWiz = AutoWizard(self, root = self.model.currentNode())
    autoWiz.exec_()

  def reportNode(self):
     ReportNodesAction(self.model)
  
  def setupUi(self, nodeActions):
     self.actionScan = QAction(self)

     icon = QIcon()
     icon.addPixmap(QPixmap(QString.fromUtf8(":/scan")), QIcon.Normal, QIcon.On)
     self.actionScan.setIcon(icon)
     self.actionScan.setObjectName(QString.fromUtf8("actionScan"))

     self.actionReport_node = QAction(self)
     icon = QIcon()
     icon.addPixmap(QPixmap(QString.fromUtf8(":/report")), QIcon.Normal, QIcon.On)
     self.actionReport_node.setIcon(icon)
     self.actionReport_node.setObjectName(QString.fromUtf8("actionReport_Node"))

     Ui_nodeActions.setupUi(self, nodeActions)
    
  def retranslateUi(self, nodeActions):
     Ui_nodeActions.retranslateUi(self, nodeActions)
     self.actionScan.setText(QApplication.translate("nodeActions", "Scan", None, QApplication.UnicodeUTF8))
     self.actionScan.setToolTip(QApplication.translate("nodeActions", "Launch recursive scan", None, QApplication.UnicodeUTF8))
     self.actionReport_node.setText(QApplication.translate("nodeActions", "Report", None, QApplication.UnicodeUTF8))
     self.actionReport_node.setToolTip(QApplication.translate("nodeActions", "Tag nodes", None, QApplication.UnicodeUTF8))
        

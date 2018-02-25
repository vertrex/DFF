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
from PyQt4.QtGui import QIcon, QPixmap, QAction, QApplication, QMenu

from dff.ui.gui.mainwindow import MainWindow
from dff.ui.gui.resources.ui_mainwindow import Ui_MainWindow

from dff.pro.ui.gui.widget.dockwidget import DockWidgetPro
from dff.pro.ui.gui.widget.nodelistwidgets import NodeListWidgetsPro
from dff.pro.ui.gui.widget.postprocessstate import PostProcessStateWidget
#from dff.pro.ui.gui.widget.reporteditor import ReportEditor
from dff.pro.ui.gui.widget.taskmanager import ProcessusPro
from dff.pro.ui.gui.widget.stdio import STDOutPro, STDErrPro
from dff.pro.ui.gui.wizard.autowizard import AutoWizard

class MainWindowPro(MainWindow):
  def __init__(self, app, debug = False):
     MainWindow.__init__(self, app, debug)

  def initConnection(self):
     MainWindow.initConnection(self)
     self.connect(self.actionWizard, SIGNAL('triggered()'), self.autoWizard)
     # self.connect(self.actionReport, SIGNAL("triggered()"), self.addReportEdit)
     # self.connect(self, SIGNAL("addReportEdit()"), self.addReportEdit)

  def initToolbarList(self):
     MainWindow.initToolbarList(self)
     self.toolbarList.insert(0, self.actionWizard)   
     # self.toolbarList.insert(len(self.toolbarList) - 1, self.actionReport)

  def initDockWidgets(self):
     MainWindow.initDockWidgets(self)
     # self.addReportEdit()
     # self.dockWidget['Report'].setVisible(False)

  def autoWizard(self):
     autoWiz = AutoWizard(self)
     autoWiz.exec_()

  def createDockWidget(self, widget, widgetName):
     return DockWidgetPro(self, widget, widgetName)

  def createProcessusWidget(self):
     return ProcessusPro(self)

  def createSTDOutWidget(self):
     return STDOutPro(self, self.debug)

  def createSTDErrWidget(self):
     return STDErrPro(self, self.debug)

  def createFirstWidgets(self):
     MainWindow.createFirstWidgets(self)
     self.wpostprocess = PostProcessStateWidget(self)
     self.addDockWidgets(self.wpostprocess, "Post Process State", False)

  def nodeListWidgets(self, parent = None):
      return NodeListWidgetsPro(parent)
   
  def addReportEdit(self):
     self.addSingleDock("Report", ReportEditor, master=True)

  def showReportEdit(self):
     self.emit(SIGNAL("addReportEdit()"))

  def setupUi(self, MainWindow):
     self.actionWizard = QAction(self)
     icon = QIcon()   
     icon.addPixmap(QPixmap(QString.fromUtf8(":/wizard")), QIcon.Normal, QIcon.Off)
     self.actionWizard.setIcon(icon)
     self.actionWizard.setObjectName(QString.fromUtf8("actionWizard"))

     # self.actionReport = QAction(self)
     # icon = QIcon()
     # icon.addPixmap(QPixmap(QString.fromUtf8(":report")), QIcon.Normal, QIcon.Off)
     # self.actionReport.setIcon(icon)
     # self.actionReport.setObjectName(QString.fromUtf8("actionReport"))

     Ui_MainWindow.setupUi(self, MainWindow)  
     self.menuFile.insertAction(self.actionOpen_evidence, self.actionWizard)
     
     # self.menuReport = QMenu(self.menubar)
     # self.menuReport.setObjectName(QString.fromUtf8("menuReport"))
     # self.menuReport.addAction(self.actionReport)
     #self.menubar.insertAction(self.menuIDE.menuAction(), self.menuReport.menuAction())
     self.retranslateUi(MainWindow)

  def retranslateUi(self, MainWindow):
     Ui_MainWindow.retranslateUi(self, MainWindow)
     self.actionWizard.setText(QApplication.translate("MainWindow", "Wizard", None, QApplication.UnicodeUTF8))
     # self.actionReport.setText(QApplication.translate("MainWindow", "Report", None, QApplication.UnicodeUTF8))
     # self.actionReport.setToolTip(QApplication.translate("MainWindow", "Open the report editor", None, QApplication.UnicodeUTF8))
     # try:
       # self.menuReport.setTitle(QApplication.translate("MainWindow", "Report", None, QApplication.UnicodeUTF8))
     # except AttributeError:
       # pass

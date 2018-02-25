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
#  Solal Jacob <sja@digital-forensic.org>
#

from PyQt4.QtGui import QWizard, QWizardPage, QLabel, QVBoxLayout, QGridLayout, QGroupBox, QRadioButton, QStyle, QWidget, QStackedWidget, QCheckBox
from PyQt4.QtCore import QSize, SIGNAL

from dff.api.loader.loader import loader
from dff.api.taskmanager.taskmanager import ppsched
from dff.api.gui.widget.devicesdialog import DevicesDialog

from dff.ui.gui.dialog.dialog import evidenceDialog, Dialog
from dff.ui.gui.resources.ui_evidencedialog import Ui_evidenceDialog

from dff.pro.ui.gui.widget.postprocessconfig import PostProcessConfigWidget
from dff.pro.ui.gui.widget.postprocessconfiganalyse import PostProcessAnalyseWidget

class AutoWizard(QWizard, Dialog):
  Page_Connector = 0
  Page_Local = 1  
  Page_Device = 2
  Page_PostProcessAnalyse = 3 
  Page_PostProcessConfig = 4
  Page_PostProcessMode = 5 
  Page_End = 6
  def __init__(self, parent = None, root = None):
     QWizard.__init__(self, parent)
     Dialog.__init__(self, parent)
     self.mainWindow = parent
     self.setWindowTitle(self.tr("DFF Wizard"))
     self.postProcessAnalysePage = None
     self.root = root

     if not root:
       self.connectorPage = ConnectorPage(self)
       self.localPage = LocalPage(self)
       self.setPage(AutoWizard.Page_Connector, self.connectorPage)
       self.setPage(AutoWizard.Page_Local, self.localPage)	
       self.devicePage = DevicePage(self)
       self.setPage(AutoWizard.Page_Device, self.devicePage)

     self.postProcessConfigPage = PostProcessConfigPage(self)
     self.setPage(AutoWizard.Page_PostProcessConfig, self.postProcessConfigPage)
       
     for module in loader().modules.itervalues():
       if module.tags.lower().find('analyse') != -1:
         self.postProcessAnalysePage = PostProcessAnalysePage(self)
         self.setPage(AutoWizard.Page_PostProcessAnalyse, self.postProcessAnalysePage)
         break
     self.postProcessMode = PostProcessMode(self)
     self.setPage(AutoWizard.Page_PostProcessMode, self.postProcessMode)
     self.endPage = EndPage(self)
     self.setPage(AutoWizard.Page_End, self.endPage)

 
  def sizeHint(self):
     return QSize(800, 600)

  def accept(self):
     if self.hasVisitedPage(AutoWizard.Page_Local):
	self.addFilesCreateProcess(self.localPage.evidence)
     elif self.hasVisitedPage(AutoWizard.Page_Device) :
	self.addDevicesCreateProcess(self.devicePage.device)
	del self.devicePage.device

     if self.hasVisitedPage(AutoWizard.Page_PostProcessConfig):
	pass
     QWizard.accept(self)

class ConnectorPage(QWizardPage):
  def __init__(self, parent = None):
     QWizardPage.__init__(self, parent)
     self.parent = parent
     self.setTitle(self.tr("Add dumps"))
    
     label = QLabel(self.tr("What do you want to analyse? "
                            "The first step is to choose some dumps for analysis. "
                            "You could load a local file, a dump or choose to mount connected devices"))
     label.setWordWrap(True)
     layout = QGridLayout() 
     layout.addWidget(label, 0, 0)

     groupBox = QGroupBox(self.tr("Dumps"))
     self.localFilesRadioButton = QRadioButton(self.tr("Add a local file"))
     self.deviceRadioButton = QRadioButton(self.tr("Add a device"))
     self.localFilesRadioButton.setChecked(True)
     groupBoxLayout = QVBoxLayout()
     groupBoxLayout.addWidget(self.localFilesRadioButton)
     groupBoxLayout.addWidget(self.deviceRadioButton)
     groupBox.setLayout(groupBoxLayout)
     layout.addWidget(groupBox, 1, 0)
     self.setLayout(layout)

  def nextId(self):
      if self.localFilesRadioButton.isChecked():
	 return AutoWizard.Page_Local
      else:
         return AutoWizard.Page_Device

  def __del__(self):
	pass #fix pyqt segfault when QGridLayout (layout ) is deleted

class LocalPage(QWizardPage):
   def __init__(self, parent = None):
     super(QWizardPage, self).__init__(parent)
     self.parent = parent
     self.setTitle(self.tr("Local files"))
     self.evidence = evidenceDialog(self)
     item = self.evidence.layout().itemAt(3)
     self.evidence.layout().removeItem(item)
     item.widget().close()
     del item
     layout = QVBoxLayout()
     layout.addWidget(self.evidence)
     self.setLayout(layout)
     
     self.connect(self.evidence.manager, SIGNAL("managerChanged"), self.completeChanged)

   def nextId(self):
     if self.parent.postProcessAnalysePage:
       return AutoWizard.Page_PostProcessAnalyse
     else:
      return AutoWizard.Page_PostProcessConfig

   def isComplete(self):
     l = len(self.evidence.manager.get("local"))
     if l > 0:
       return True
     else:
       return False
     return False

class DevicePage(QWizardPage):
   def __init__(self, parent = None):
     super(QWizardPage, self).__init__(parent)
     self.parent = parent
     self.setTitle("Devices")
     self.device = DevicesDialog(self)
     item = self.device.layout().itemAt(3)
     self.device.layout().removeItem(item)
     item.widget().close()
     del item
     layout = QVBoxLayout()
     layout.addWidget(self.device)
     self.setLayout(layout) 	

   def nextId(self):
     if self.parent.postProcessAnalysePage:
       return AutoWizard.Page_PostProcessAnalyse
     else:
      return AutoWizard.Page_PostProcessConfig

class PostProcessConfigPage(QWizardPage):
  def __init__(self, parent = None):
     QWizardPage.__init__(self, parent)
     self.parent = parent
     self.setTitle(self.tr("Modules"))
     label = QLabel(self.tr("Choose modules that will be automatically applied."))
     label.setWordWrap(True)
     layout = QVBoxLayout()
     layout.addWidget(label)
     self.widget = PostProcessConfigWidget()
     layout.addWidget(self.widget)
     self.setLayout(layout)

  def initializePage(self):
     self.widget.fillFromAnalyse()	

class PostProcessAnalysePage(QWizardPage):
  def __init__(self, parent = None):
     QWizardPage.__init__(self, parent)
     self.parent = parent
     self.setTitle(self.tr("Analyse"))
     label = QLabel(self.tr("You can choose some analyzis tasks which will autoconfigure modules to automaticallty apply during processing."))
     label.setWordWrap(True)
     layout = QVBoxLayout()
     layout.addWidget(label)
     self.widget = PostProcessAnalyseWidget() #XXX asks to auto-fill from analyse ! 
     layout.addWidget(self.widget) 
     self.setLayout(layout)

class PostProcessMode(QWizardPage):
  def __init__(self, parent = None):
     QWizardPage.__init__(self, parent)
     self.parent = parent
     self.setTitle(self.tr("Processing mode"))
     label = QLabel(self.tr("You can choose between a fully automated mode, and semi-automatic mode. "
                            "Full mode means all compatible modules will be applied without prompting you. "
                            "Semi-auto mode means that for each applied module and for each scan you will be asked to continue or to cancel. "
                            "If you don't know what to choose, select Full-automatic"))
     label.setWordWrap(True)
     layout = QGridLayout()
     layout.addWidget(label, 0, 0)
     groupBox = QGroupBox("Mode")
     self.fullBoxRadioButton = QRadioButton("F&ull Auto")
     self.semiBoxRadioButton = QRadioButton("S&emi Auto")
     self.fullBoxRadioButton.setChecked(True)
     groupBoxLayout = QVBoxLayout()
     groupBoxLayout.addWidget(self.fullBoxRadioButton)
     groupBoxLayout.addWidget(self.semiBoxRadioButton)
     groupBox.setLayout(groupBoxLayout)
     layout.addWidget(groupBox, 1, 0)
     self.setLayout(layout)

  def validatePage(self):
     if self.fullBoxRadioButton.isChecked():
       ppsched.fullAutoMode(True)
     else:
       ppsched.fullAutoMode(False)
     return True

  def __del__(self):
	pass #fix pyqt segfault when QGridLayout (layout ) is deleted

class EndPage(QWizardPage):
  def __init__(self, parent = None):
     QWizardPage.__init__(self, parent)
     self.parent = parent
     self.setTitle(self.tr("Finish"))
     label = QLabel(self.tr("The wizard is finished and all your choice will be applied when clicking the 'finish' button. "
                            "You can also click previous to check and change your options. "
                            "Once clicked, a Scanner tab will be created to show you the overall progression of the analysis. At the end the analysis some results will be poped-up and some will be automatically added to the report. "
                            "Think to look at the taskmanager and start browsing if you want."))
     label.setWordWrap(True)
     layout = QVBoxLayout()
     layout.addWidget(label)
     self.setLayout(layout)

  def validatePage(self):
     if self.parent.root:
	ppsched.enqueueRegister(self.parent.root)
     return True

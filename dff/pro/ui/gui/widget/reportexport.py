import os

from PyQt4.QtCore import QObject, SIGNAL
from PyQt4.QtGui import QDialog, QLabel, QProgressBar, QPushButton, QVBoxLayout, QCheckBox, QHBoxLayout, QFileDialog, QLineEdit, QMessageBox

from dff.api.events.libevents import EventHandler
from dff.api.vfs.extract import Extract

from dff.pro.api.report.manager import ReportManager
from dff.pro.api.report.page import ReportPage
from dff.pro.api.report.fragments import ReportPageFragment

class ReportExportProgress(QObject):
  def __init__(self, name, eventCount, eventStart, eventFinish, child = None):
     QObject.__init__(self)
     self.name = name
     self.eventCount = eventCount
     self.eventStart = eventStart
     self.eventFinish = eventFinish
     self.child = child
     self.label = QLabel()
     self.label.setWordWrap(True)  
     self.bar = QProgressBar()
     self.bar.setFormat(" %v/%m (%p%)")
     self.reset()

  def reset(self):
     self.title = ""
     self.current = 0
     self.count = 0

  def event(self, event):
     if event.type == self.eventStart:
       self.title = event.value.value()
       if self.child:
         self.child.reset()
     if event.type == self.eventFinish:
       self.current += 1
       self.bar.setValue(self.current) 
     if event.type == self.eventCount:
       self.count = event.value.value()
       self.bar.setValue(0)
       self.bar.setMaximum(self.count)
     self.label.setText(self.tr("Extraction ") + self.name + " : " + str(self.title))

class ReportExportProgressItems(QObject):
  def __init__(self):
     QObject.__init__(self)
     self.eventCount =  ReportManager.EventExportItems
     self.eventFinish = [ReportManager.EventExportCategoryFinish, ReportPage.EventExportFinish, ReportPageFragment.EventWriteFinish, ReportPageFragment.EventWriteElementFinish]
     self.label = QLabel(self.tr("Extracting report"))
     self.bar = QProgressBar()
     self.bar.setFormat(" %v/%m (%p%)")
     self.reset() 

  def reset(self):
     self.count = 0
     self.current = 0 

  def event(self, event):
     if event.type == self.eventCount:   
       self.count = event.value.value()
       self.bar.setValue(0)
       self.bar.setMaximum(self.count)
     if event.type in self.eventFinish:
       self.current += 1
       self.bar.setValue(self.current)

class ReportExportInformations(QMessageBox):
  def __init__(self, reportExportDialog, status):
     self.__reportExportDialog = reportExportDialog
     self.__status = status
     self.__reportManager = ReportManager()
     QMessageBox.__init__(self, QMessageBox.Information, "", "", QMessageBox.Close)
     self.setWindowTitle(self.tr("Finished")) 
     self.setText(self.__message())
     self.setDetailedText(self.__detailedMessage())

  def __detailedMessage(self):
     msg = self.tr("Extraction path ")
     msg += self.__reportManager.exportPath() + "\n"
     if self.__status == True: 
       msg += str(self.__reportManager.exportSize()) + self.tr(" bytes extracted") + '\n'
     msg += str(self.__reportExportDialog.items.count) + self.tr(" items extracted") + '\n'
     return msg 

  def __message(self):
    if self.__status == True:
      msg = self.tr("Extraction finished successfully") + '\n' 
    else:
      msg = self.tr("Extraction failed") + '\n'
    return msg

class ReportExportDialog(QDialog, EventHandler):
  def __init__(self):
    QDialog.__init__(self, None)
    EventHandler.__init__(self)
    self.reportManager = ReportManager()
    self.reportManager.connection(self)
    self.setModal(True)
    self.detail = False
    self.items = ReportExportProgressItems()
    self.__optionsDialog = None

    self.elements = ReportExportProgress(self.tr("of elements"), ReportPageFragment.EventWriteElements, ReportPageFragment.EventWriteElementStart, ReportPageFragment.EventWriteElementFinish)
    self.fragments = ReportExportProgress(self.tr("of fragments"), ReportPage.EventExportFragments, ReportPageFragment.EventWriteStart, ReportPageFragment.EventWriteFinish, self.elements)
    self.pages = ReportExportProgress(self.tr("of pages"), ReportManager.EventExportPages, ReportPage.EventExportStart, ReportPage.EventExportFinish, self.fragments)
    self.category = ReportExportProgress(self.tr("of category"), ReportManager.EventExportCategories, ReportManager.EventExportCategoryStart, ReportManager.EventExportCategoryFinish, self.pages)

    self.progresses = [self.category, self.pages, self.fragments, self.elements]
    self.detailButton = QPushButton("<<< " + self.tr("Show details"))
    self.connect(self.detailButton, SIGNAL("clicked()"), self.showDetail)
    self.cancelButton = QPushButton("&" + self.tr("Cancel"))
    self.connect(self.cancelButton, SIGNAL("clicked()"), self.cancel)

    self.hboxLayout = QVBoxLayout(self)
    self.hboxLayout.addWidget(self.items.label)
    self.hboxLayout.addWidget(self.items.bar)
    for progress in self.progresses:
       self.hboxLayout.addWidget(progress.label)
       progress.label.hide()
       self.hboxLayout.addWidget(progress.bar)
       progress.bar.hide()
    self.hboxLayout.addWidget(self.detailButton)
    self.hboxLayout.addWidget(self.cancelButton)
    self.setLayout(self.hboxLayout)

  def showDetail(self):
     self.detail = not self.detail
     if self.detail:
       self.detailButton.setText(">>> " + self.tr("Hide details"))
       for progress in self.progresses:
          progress.bar.show()
          progress.label.show()
     else: 
       self.detailButton.setText("<<< " + self.tr("Show details"))
       for progress in self.progresses:
          progress.bar.hide()
          progress.label.hide()
     if self.sizeHint().width() > self.size().width():
       self.resize(self.sizeHint().width(), self.sizeHint().height())
     else:
       self.resize(self.size().width(), self.sizeHint().height())
        
  def Event(self, event):
     self.items.event(event)
     for progress in self.progresses:
        progress.event(event)

  def checkExportFreeSpace(self, exportContent):
     exportPath = self.reportManager.exportPath()
     if os.name == "nt":
       exportPath = exportPath[:exportPath.rfind("\\")]
     else:
       exportPath = exportPath[:exportPath.rfind("/")]
     freeSpace = Extract.freeSpace(exportPath)
     exportSize = self.reportManager.exportSize(exportContent)
     if freeSpace < exportSize:
       msg = self.tr("Not enough free space to extract files.") + '\n'
       msg += str(freeSpace) + self.tr(" bytes of free space for ") + str(exportSize) + self.tr(" bytes of data to extract.") + '\n'
       msg += self.tr("Choose an other directory ?")
       return QMessageBox.warning(self, self.tr("Export"), msg, QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
     return QMessageBox.No

  def optionsDialog(self, exportContent = False):
     if self.__optionsDialog:
       return self.__optionsDialog
     else:
       self.__optionsDialog = ReportExportOptionsDialog(exportContent)
       return self.__optionsDialog

  def export(self, exportContent = True, askOptions = False, checkExportSize = True, displayInformations = True):
     if askOptions:
       self.optionsDialog(exportContent).exec_()
       exportContent = self.optionsDialog().exportContent()
     if checkExportSize:
       choice = self.checkExportFreeSpace(exportContent)
       if choice == QMessageBox.No:
         return self.__export(exportContent, displayInformations) 
       elif choice == QMessageBox.Yes:
        self.export(exportContent, askOptions = True, checkExportSize = True, displayInformations = True) 
     else:
       return self.__export(exportContent, displayInformations)

  def __export(self, exportContent, displayInformations = True):
     self.show()
     try:
       self.reportManager.export(exportContent)
       status = True
       self.accept() 
     except Exception as e:
       print 'Error : Export failed ', e
       self.reject()
       status = False
       self.reject()
     if displayInformations:
       ReportExportInformations(self, status).exec_() 
     return status

  def cancel(self):
     self.reportManager.exportCancel()
     QDialog.reject(self)

  def __del__(self):
     self.reportManager.deconnection(self)

class ReportExportOptionsDialog(QDialog):
  def __init__(self, exportContent = False):
     QDialog.__init__(self)
     self.setWindowTitle(self.tr("Export options"))
     self.reportManager = ReportManager()
     layout = QVBoxLayout()

     self.extractContentCheckBox = QCheckBox(self.tr("E&xtract content"))
     if exportContent:
       self.extractContentCheckBox.setChecked(True)
     else:
       self.extractContentCheckBox.setChecked(False)
     layout.addWidget(self.extractContentCheckBox)

     directoryPathLayout = QHBoxLayout()
     pathLabel = QLabel(self.tr("Report extraction path :"))
     self.pathLineEdit = QLineEdit(self.reportManager.export_path)
     self.pathLineEdit.setReadOnly(True)
     pathButton = QPushButton("...")
     self.connect(pathButton, SIGNAL("clicked()"), self.askPath)
     directoryPathLayout.addWidget(pathLabel)
     directoryPathLayout.addWidget(self.pathLineEdit)
     directoryPathLayout.addWidget(pathButton)
     layout.addLayout(directoryPathLayout)
    
     buttonLayout = QHBoxLayout() 
     self.buttonOk = QPushButton("O&k")
     self.connect(self.buttonOk, SIGNAL("clicked()"), self.accept)
     self.buttonCancel = QPushButton("C&ancel")
     self.connect(self.buttonCancel, SIGNAL("clicked()"), self.reject)

     buttonLayout.addWidget(self.buttonOk)
     buttonLayout.addWidget(self.buttonCancel)
     layout.addLayout(buttonLayout)
     self.setLayout(layout)

  def askPath(self):
     directory = QFileDialog.getExistingDirectory(self, self.tr("Report extraction directory"), self.reportManager.export_path)
     if len(directory):
       directory = os.path.join(str(directory.toUtf8()), 'dff-report')
       self.pathLineEdit.clear()
       self.pathLineEdit.insert(directory)
       self.reportManager.setExportPath(directory)

  def exportContent(self):
     if self.extractContentCheckBox.isChecked():
       return True
     else:
       return False

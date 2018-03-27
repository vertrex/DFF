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
import os

from PyQt4.QtCore import SIGNAL
from PyQt4.QtGui import QDialog, QMessageBox,QVBoxLayout, QHBoxLayout, QDialogButtonBox, QLabel, QLineEdit, QPushButton, QFileDialog, QRadioButton, QGridLayout, QGroupBox, QCheckBox

from dff.api.vfs.exportcsv import CSV

from dff.ui.gui.dialog.selectattributes import SelectAttributesWizard#AttributeSelector

class ExportCSVDialog(QDialog):
  def __init__(self, parent, nodes, selectedAttributes): #current column 
    QDialog.__init__(self, parent)
    self.nodes = nodes
    self.exportPath = os.path.join(os.path.expanduser("~"), "dff.csv")
    self.attributes = selectedAttributes 
    self.split = False

    self.dialogLayout = QVBoxLayout()
    self.setLayout(self.dialogLayout)
    self.setPathEdit()
    self.setAttributesSelection()
    self.setSplitCheckBox()
    self.setButtons()

  def setButtons(self):
    self.dialogButtonsLayout = QHBoxLayout()
    self.dialogButtonsBox = QDialogButtonBox()
    self.dialogButtonsBox.setStandardButtons(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
    self.connect(self.dialogButtonsBox, SIGNAL("accepted()"), self.accept)
    self.connect(self.dialogButtonsBox, SIGNAL("rejected()"), self.reject)
    self.dialogButtonsLayout.addWidget(self.dialogButtonsBox)
    self.dialogLayout.addLayout(self.dialogButtonsLayout)

  def setSplitCheckBox(self):
     self.splitCheckBox = QCheckBox("Split file every 65536 lines") 
     self.connect(self.splitCheckBox, SIGNAL("stateChanged(int)"), self.setSplit)
     self.dialogLayout.addWidget(self.splitCheckBox)

  def setSplit(self, state):
     if state:
       self.split = True
     else:
       self.split = False

  def setAttributesSelection(self):
    self.attributesSelectionLayout = QHBoxLayout()
    self.attributesSelectionLabel = QLabel(self.tr("Choose CSV column :"))
    attributesSelectionButton = QPushButton("...")
    self.attributesSelectionLayout.addWidget(self.attributesSelectionLabel)
    self.attributesSelectionLayout.addWidget(attributesSelectionButton)
    self.dialogLayout.addLayout(self.attributesSelectionLayout)
    self.connect(attributesSelectionButton, SIGNAL("clicked()"), self.askColumn)

  def askColumn(self):
      #if timeline node  
     selectAttributesWizard = SelectAttributesWizard(self.parent().model(), self.attributes, self.parent().model().defaultAttributes())  # need model by default for list check and defalt atributs, 'current selected file as steel a meaning' rather always parse list ? , use attribute selector ? 
     if selectAttributesWizard.exec_() == 1: #get choosen attribtes iand set to list 
     #    if iret == 1:
      self.attributes = selectAttributesWizard.getSelectedAttributes()

  def setPathEdit(self):
    self.exportPathLayout = QHBoxLayout()
    self.exportPathLabel = QLabel(self.tr("Path of csv file:"))
    self.exportPathLineEdit = QLineEdit(self.exportPath)
    self.exportPathLineEdit.setReadOnly(True)
    exportPathButton = QPushButton("...")

    self.exportPathLayout.addWidget(self.exportPathLabel)
    self.exportPathLayout.addWidget(self.exportPathLineEdit)
    self.exportPathLayout.addWidget(exportPathButton)
    self.dialogLayout.addLayout(self.exportPathLayout)
    self.connect(exportPathButton, SIGNAL("clicked()"), self.askExportPath)

  def askExportPath(self):
    newPath = QFileDialog().getSaveFileName(self, self.tr("CSV path"), self.exportPath)
    if len(newPath):
      self.exportPath = unicode(newPath.toUtf8(), 'utf-8')
      self.exportPathLineEdit.clear()
      self.exportPathLineEdit.insert(self.exportPath)

  def accept(self):
    #XXX thread me 
    self.exportCSV()
    QDialog.accept(self)
    #show advancement in widget (next)

  def exportCSV(self):
    try:
      csv = CSV()
      ##if not self.timeLineButton.isChecked():
      csv.exportNodes(self.exportPath, self.nodes, self.attributes, self.split)
    except Exception as e:
      msg = QMessageBox(self)
      msg.setWindowTitle(self.tr("Export to CSV error"))
      msg.setText(self.tr("An issue occured while exporting to CSV"))
      msg.setIcon(QMessageBox.Warning)
      msg.setDetailedText(str(e))
      msg.setStandardButtons(QMessageBox.Ok)
      ret = msg.exec_()

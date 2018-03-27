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
#  Solal Jacob <sja@digital-forensic.org>
#  Jeremy MOUNIER <sja@digital-forensic.org>
# 
from PyQt4.QtGui import QFileDialog, QMessageBox, QInputDialog, QTableWidget, QTableWidgetItem, QDialog, QHBoxLayout, QPushButton, QVBoxLayout, QSplitter, QDialogButtonBox, QFormLayout, QWidget, QComboBox, QLabel, QPixmap, QTreeView, QStandardItemModel, QStandardItem
from PyQt4.QtCore import QString, Qt, SIGNAL, SLOT, QEvent, QModelIndex

from dff.api.taskmanager import *
from dff.api.taskmanager.taskmanager import *
from dff.api.loader import *
from dff.api.vfs import vfs
from dff.api.devices.devices import Devices, Logical

from dff.ui.gui.resources.ui_devicesdialog import Ui_DevicesDialog


class TreeComboBox(QComboBox):
    def __init__(self, *args):
        QComboBox.__init__(self, *args)
        self.__skip_next_hide = False
        tree_view = QTreeView(self)
        tree_view.setHeaderHidden(True)
        #tree_view.setFrameShape(QFrame.NoFrame)
        #tree_view.setEditTriggers(tree_view.NoEditTriggers)
        tree_view.setAlternatingRowColors(True)
        tree_view.setSelectionBehavior(tree_view.SelectRows)
        tree_view.setWordWrap(True)
        #tree_view.setAllColumnsShowFocus(True)
        self.setView(tree_view)
        self.view().viewport().installEventFilter(self)


    def showPopup(self):
        self.setRootModelIndex(QModelIndex())
        QComboBox.showPopup(self)


    def hidePopup(self):
        self.setRootModelIndex(self.view().currentIndex().parent())
        self.setCurrentIndex(self.view().currentIndex().row())
        if self.__skip_next_hide:
            self.__skip_next_hide = False
        else:
            pass
            QComboBox.hidePopup(self)


    def selectIndex(self, index):
        self.setRootModelIndex(index.parent())
        self.setCurrentIndex(index.row())


    def eventFilter(self, object, event):
        if event.type() == QEvent.MouseButtonPress and object is self.view().viewport():
            index = self.view().indexAt(event.pos())
            self.__skip_next_hide = not self.view().visualRect(index).contains(event.pos())
        return False



class DevicesDialog(QDialog, Ui_DevicesDialog):
  def __init__(self, parent = None):
    QDialog.__init__(self)
    self.setupUi(self)
    self.selectedDevice = None
    self.listdevices = {}
    self.devices = Devices()
    self.logical = Logical()
    self.combodevice = TreeComboBox()
    self.gridLayout.addWidget(self.combodevice, 0, 1, 1, 1)
    self.__model = QStandardItemModel()
    
    lidx = 0
    if len(self.logical):
        logicalitems = QStandardItem(self.tr("Logical drives"))
        self.__model.appendRow(logicalitems)
        for lidx in range(0, len(self.logical)):
            logicalitem = QStandardItem(self.logical[lidx].model())
            logicalitems.appendRow(logicalitem)
            self.listdevices[lidx] = self.logical[lidx]
        lidx += 1

    if len(self.devices):
        physicalitems = QStandardItem(self.tr("Physical drives"))
        self.__model.appendRow(physicalitems)
        for pidx in range(0, len(self.devices)):
            model = self.devices[pidx].model()
            if model != "Unknown":
              physicalitem = QStandardItem(self.devices[pidx].blockDevice() + " (" + model + ")")
            else:
              physicalitem = QStandardItem(self.devices[pidx].blockDevice())
            physicalitems.appendRow(physicalitem)
            self.listdevices[lidx+pidx] = self.devices[pidx]
    self.combodevice.setModel(self.__model)
    self.combodevice.view().expandAll()

    if len(self.devices):
      self.setDeviceInformations(self.devices[0], True)
      self.selectedDevice = self.devices[0]
    self.connect(self.combodevice, SIGNAL("currentIndexChanged(int)"), self.deviceChanged) 

    
  def __del__(self):
      del self.devices
      del self.logical


  def setDeviceInformations(self, device, init=False):
      self.blockdevice.setText(QString.fromUtf8(device.blockDevice()))
      self.model.setText(QString.fromUtf8(device.model()))
      self.serial.setText(QString.fromUtf8(device.serialNumber()))
      self.size.setText(str(device.size()))


  def deviceChanged(self, index):
      parent = self.combodevice.view().currentIndex().parent()
      if parent != QModelIndex():
          if parent.row() == 1:
              index += len(self.logical)    
      self.setDeviceInformations(self.listdevices[index])
      self.selectedDevice = self.listdevices[index]

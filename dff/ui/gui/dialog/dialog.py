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
#  Jeremy Mounier <jmo@digital-forensic.org>
#
import os, sys, traceback

from PyQt4.QtGui import QFileDialog, QMessageBox, QInputDialog, QDialog, QDialogButtonBox, QComboBox, QPushButton, QFormLayout, QHBoxLayout, QPixmap, QLabel, QApplication
from PyQt4.QtCore import QObject, QString, SIGNAL, SLOT, Qt, QEvent, QDir

from dff.api.vfs import vfs
from dff.api.loader import loader 
from dff.api.taskmanager.taskmanager import TaskManager 
from dff.api.types.libtypes import typeId
from dff.api.devices.devices import Devices
from dff.api.gui.widget.devicesdialog import DevicesDialog
from dff.api.gui.widget.layoutmanager import layoutManager  

from dff.ui.gui.dialog.preferences import Preferences
from dff.ui.gui.resources.ui_about import Ui_About
from dff.ui.gui.resources.ui_evidencedialog import Ui_evidenceDialog
from dff.ui.gui.widget.modulesmanager import modulesManager, browserDialog 

class Dialog(QObject):
  def __init__(self, parent):
     QObject.__init__(self)
     self.parent = parent 
     self.vfs = vfs.vfs()
     self.taskmanager = TaskManager()
     self.loader = loader.loader()

  def preferences(self):
    """Open a preferences dialog"""
    
    pref = Preferences(self.parent)
    ret = pref.exec_()
    if ret:
      pass

  def addDevices(self):
       """Open a device list dialog"""
       dev = DevicesDialog(self.parent)
       if dev.exec_():
	 self.addDevicesCreateProcess(dev)
       del dev

  def addDevicesCreateProcess(self, dev):
	 if dev.selectedDevice:
           args = {}
	   args["path"] = str(dev.selectedDevice.blockDevice())
	   args["parent"] = self.vfs.getnode("/Local devices")
	   args["size"] = long(dev.selectedDevice.size())
	   exec_type = ["thread", "gui"]
	   try:
             if os.name == "nt":
	       args["name"] = str(dev.selectedDevice.model())
             conf = self.loader.get_conf(str("devices"))
             genargs = conf.generate(args)
             self.taskmanager.add("devices", genargs, exec_type)	
           except RuntimeError:
             err_type, err_value, err_traceback = sys.exc_info()
             err_trace =  traceback.format_tb(err_traceback)
             err_typeval = traceback.format_exception_only(err_type, err_value)
             terr = QString()
             detailerr = QString()
             for err in err_trace:
               detailerr.append(err)
               for errw in err_typeval:
                 terr.append(errw)
                 detailerr.append(err)
             self.messageBox(terr, detailerr)

  def addFiles(self):
        """ Open a Dialog for select a file and add in VFS """
        edialog = evidenceDialog(self.parent)
        ir = edialog.exec_()
        if ir > 0:
	  self.addFilesCreateProcess(edialog)

  def addFilesCreateProcess(self, edialog):
          args = {}
          paths = edialog.manager.get("local")
          if edialog.rawcheck.isChecked():
            module = "local"
            args["path"] = paths
	    args["parent"] = self.vfs.getnode('/Logical files')
          elif edialog.ewfcheck.isChecked():
            module = "ewf"
            args["files"] = paths
	    args["parent"] = self.vfs.getnode('/Logical files')
          else:
            module = "aff"
            args["path"] = paths
	    args["parent"] = self.vfs.getnode('/Logical files')
          self.conf = self.loader.get_conf(str(module))
          try:
            genargs = self.conf.generate(args)
            self.taskmanager.add(str(module), genargs, ["thread", "gui"])
          except RuntimeError:
            err_type, err_value, err_traceback = sys.exc_info()
            err_trace =  traceback.format_tb(err_traceback)
            err_typeval = traceback.format_exception_only(err_type, err_value)
            terr = QString()
            detailerr = QString()
            for err in err_trace:
              detailerr.append(err)
              for errw in err_typeval:
                terr.append(errw)
                detailerr.append(err)
            self.messageBox(terr, detailerr)

  def messageBox(self, coretxt, detail):
    msg = QMessageBox()
    msg.setWindowTitle(self.tr("Error in configuration"))
    msg.setText(self.tr("An error was detected in the configuration"))
    msg.setInformativeText(coretxt)
    msg.setIcon(QMessageBox.Critical)
    msg.setDetailedText(detail)
    msg.setStandardButtons(QMessageBox.Ok)
    ret = msg.exec_()
 
  def loadDriver(self):
        sFileName = QFileDialog.getOpenFileName(self.parent, self.parent.actionLoadModule.toolTip(), os.path.expanduser('~'),  "Modules(*.py)")
        if (sFileName) :
            self.loader.do_load(str(sFileName.toUtf8()))

  def about(self):
        """ Open a About Dialog """
        about = About()
        about.exec_()

  def manager(self):
        """ Open module browser dialog """
        module = browserDialog(self.parent)
        ir = module.exec_()
        if ir > 0:
          module.browser.execute()

class About(QDialog, Ui_About):
  def __init__(self):
    super(QDialog, self).__init__()
    self.setupUi(self)
    self.label.setText(self.label.text().arg(QApplication.instance().applicationVersion()))

  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
      self.label.setText(self.label.text().arg(QApplication.instance().applicationVersion()))
    else:
      QDialog.changeEvent(self, event)


class evidenceDialog(QDialog, Ui_evidenceDialog):
  def __init__(self, parent):
    super(QDialog, self).__init__()
    self.setupUi(self)
    self.loader = loader.loader()
    self.createShape()

  def createShape(self):
    """ Removes EWF if not in modules

    Set itemData for easy access without taking care of text (can be
    translated).
    TODO Futur : Get all DFF connectors
    """    
    if "ewf" not in self.loader.modules:
      self.ewfcheck.setEnabled(False)
    if "aff" not in self.loader.modules:
      self.affcheck.setEnabled(False)
    self.rawcheck.setChecked(True)

    self.manager = layoutManager()

    self.manager.addPathList("local", [])

    self.pathlayout.addWidget(self.manager)

  def keyPressEvent(self, event):
     if self.parent():
       self.parent().keyPressEvent(event)
     else:
       QDialog.keyPressEvent(self, event)	

  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
      self.label.setText(self.label.text().arg(QApplication.instance().applicationVersion()))
    else:
      QDialog.changeEvent(self, event)

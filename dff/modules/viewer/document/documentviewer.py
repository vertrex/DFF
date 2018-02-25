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
# 

__dff_module_documentviewer_version__ = "1.0.0"

from PyQt4.QtCore import SIGNAL, QThread, QObject, SLOT

from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.types.libtypes import Argument, typeId

from documentconverter import DocumentConverter
from pdfwidget import PDFWidget

class QConverter(QObject):
  def __init__(self):
    QObject.__init__(self)
    
  def convert(self):
    try:
      self.converter = DocumentConverter()
      pdfDocument = self.converter.convert(self.node)
      self.viewer.emit(SIGNAL("converterFinish"), pdfDocument)
    except Exception as e:
      self.viewer.emit(SIGNAL("converterError"), e)
  
class DocumentViewer(PDFWidget, Script):
  def __init__(self):
    Script.__init__(self, "Document viewer")
    self.name = "Document viewer"
    self.thread = None
    self.converter = None
    self.askToClose = False

  def start(self, args):
    self.node = args["file"].value()
    try:
      self.preview = args["preview"].value()
    except IndexError:
      self.preview = False
 
  def converterError(self, error):
     self.thread.quit()
     if self.askToClose:
       self.close()
     else:
       self.setError("Error while converting document: " + self.node.name() + "\n" + str(error))
 
  def converterFinish(self, pdfDocument):
     self.thread.quit()
     if self.askToClose:
       self.close()
     else:
       self.setDocument(pdfDocument)

  def closeEvent(self, event):
    self.askToClose = True 
    if self.thread and self.thread.isRunning():
      event.ignore()
    else:
      event.accept()

  def g_display(self):
    PDFWidget.__init__(self)
    if self.node.dataType() == "document/pdf":
      vfile = self.node.open()
      pdfDocument = vfile.read()
      vfile.close()
      self.setDocument(pdfDocument)
    else:
      self.setMessage("Loading : " + self.node.name())
      self.converter = QConverter()
      self.thread = QThread()
      self.converter.moveToThread(self.thread)
      self.converter.node = self.node
      self.converter.viewer = self
      self.connect(self.thread, SIGNAL("started()"), self.converter.convert)
      self.connect(self, SIGNAL("converterFinish"), self.converterFinish)
      self.connect(self, SIGNAL("converterError"), self.converterError)
      self.thread.start()

  def updateWidget(self):
	pass

class documentviewer(Module):
  """Document viewer"""
  def __init__(self):
    Module.__init__(self, "Document viewer", DocumentViewer)
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                           "name": "file",
                           "description": "File to display"})
    self.conf.addArgument({"name": "preview",
			   "description": "Preview mode",
			   "input": Argument.Empty})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "type of file compatible with this module",
 	                   "values": ["document", "windows/compound"]})
    self.tags = "Viewers"
    self.flags = ["gui"]
    self.icon = ":pdf" #change XXX

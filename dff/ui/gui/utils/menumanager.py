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
#  Jeremy Mounier <jmo@arxsys.fr>
#

import base64, os

from PyQt4 import QtCore, QtGui #, QtWebKit

from PyQt4.QtGui import QMenu, QIcon, QWidget, QCursor, QApplication, QAction, QMessageBox, QImage, QIcon, QPixmap, QInputDialog, QLineEdit, QDialog
from PyQt4.QtCore import SIGNAL, SLOT, QObject, QEvent, QString, QBuffer, QByteArray

from dff.api.loader import loader
from dff.api.vfs.libvfs import VFS, ABSOLUTE_ATTR_NAME
from dff.api.types.libtypes import typeId, Variant
from dff.api.taskmanager.taskmanager import TaskManager 
from dff.api.taskmanager.processus import ProcessusManager
from dff.api.report.manager import ReportManager

from dff.api.gui.dialog.extractor import Extractor

from dff.ui.gui.utils.utils import Utils
from dff.ui.gui.utils.action import newAction, Action
from dff.ui.gui.utils.menu import tagMenu, selectionMenu, BookmarkManager
from dff.ui.gui.resources.ui_nodeactions import Ui_nodeActions

from dff.ui.gui.widget.reportselect import ReportSelectDialog
from dff.ui.gui.wizard.autowizard import AutoWizard

modulePriority = {}

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

class MenuManager(QWidget, Ui_nodeActions):
  def __init__(self, selection, listmodel):
    super(QWidget, self).__init__()
    self.__iconView = False
    self.setupUi(self)
    self.processusManager = ProcessusManager()
    self.loader = loader.loader()
    self.lmodules = self.loader.modules
    self.taskmanager = TaskManager()
    self.mainwindow = QApplication.instance().mainWindow
    self.createActions()
    self.checkedSelection = selection
    self.selection = None
    self.model = listmodel
    self.bookManager = BookmarkManager(self.model)
    #self.document = QtWebKit.QWebView()
    #self.document.loadFinished.connect(self.__print)
    self.__corrupt = base64.b64encode(str(QtGui.QImage(":file_broken.png").bits()))
    self.__printer = QtGui.QPrinter(QtGui.QPrinter.ScreenResolution)
    self.__printer.setOutputFormat(QtGui.QPrinter.PdfFormat)
    self.__printer.setPaperSize(QtGui.QPrinter.A4)
    self.__printer.setFullPage(True)

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

  def setIconView(self, enable):
    self.__iconView = enable

  def createActions(self):
    self.extractor = Extractor(self.mainwindow)
    self.connect(self.extractor, SIGNAL("filled"), self.launchExtract)
    self.actionOpen.setParent(self.mainwindow)
    self.actionOpen_in_new_tab.setParent(self.mainwindow)
    self.copyToHtmlTable = QAction(self.tr("Export selection to pdf"), self)
    self.copyToHtmlTable.triggered.connect(self.__exportToPdf)
    self.connect(self.actionOpen, SIGNAL("triggered()"), self.openDefault)
    self.connect(self.actionOpen_in_new_tab, SIGNAL("triggered()"), self.openAsNewTab)
    self.connect(self.actionOpen_parent_folder, SIGNAL("triggered()"), self.openParentFolder)
    self.connect(self.actionHex_viewer, SIGNAL("triggered()"), self.launchHexedit)
    self.connect(self.actionExtract, SIGNAL("triggered()"), self.extractNodes)
    self.connect(self.actionBookmark, SIGNAL("triggered()"), self.bookmark)
    self.connect(self.actionScan, SIGNAL('triggered()'), self.scan)
    self.connect(self.actionReport_node, SIGNAL('triggered()'), self.reportNode)

  def createMenu(self):
    nodeclicked = self.model.currentNode()
    self.mainmenu = QMenu(self.mainwindow)
    self.selection = self.model.currentNode()
    self.setOpenRelevant()
    self.setOpenWith()
    self.mainmenu.addAction(self.actionOpen)
    self.mainmenu.addAction(self.actionOpen_with)
    self.mainmenu.addAction(self.actionOpen_in_new_tab)
    self.mainmenu.addAction(self.actionOpen_parent_folder)
    if nodeclicked.isDir() or nodeclicked.hasChildren():
      self.actionOpen_parent_folder.setVisible(False)
      self.actionOpen_parent_folder.setEnabled(False)
      self.actionOpen_in_new_tab.setVisible(True)
      self.actionOpen_in_new_tab.setEnabled(True)
    else:
      self.actionOpen_in_new_tab.setVisible(False)
      self.actionOpen_in_new_tab.setEnabled(False)
      self.actionOpen_parent_folder.setVisible(True)
      self.actionOpen_parent_folder.setEnabled(True)

    self.mainmenu.addSeparator()
    selection = selectionMenu(self, self.model)
    self.mainmenu.addMenu(selection)
    tags = tagMenu(self, self.mainwindow, self.model)
    self.actionTags.setMenu(tags)
    self.mainmenu.addAction(self.actionTags)
    self.mainmenu.addAction(self.actionBookmark)
    if nodeclicked.path().find('/Bookmarks/') != -1:
      self.mainmenu.addAction(QIcon(":trash"), self.tr("Delete bookmark"), self.deleteBookmark)
    self.bookseparator = self.mainmenu.addSeparator()
    self.mainmenu.addAction(self.actionHex_viewer)
    self.mainmenu.addAction(self.actionExtract)
    if self.__iconView:
      self.mainmenu.addAction(self.copyToHtmlTable)
    self.mainmenu.popup(QCursor.pos())
    self.mainmenu.insertSeparator(self.actionOpen_parent_folder)
    self.mainmenu.insertAction(self.actionOpen_parent_folder, self.actionScan)
    self.mainmenu.addSeparator()
    self.mainmenu.insertAction(self.bookseparator, self.actionReport_node)
    self.mainmenu.show()

  def reportNode(self):
     ReportNodesAction(self.model)

  def scan(self):
    autoWiz = AutoWizard(self, root = self.model.currentNode())
    autoWiz.exec_()

  def deleteBookmark(self):
    vfs = VFS.Get()
    try :
      vfs.unregister(self.model.currentNode())
    except Exception as e:
      print 'TreeMenu.deleteNode exceptions : ', str(e)

  def setOpenRelevant(self):
    if self.selection != None:
      node = self.selection
      modules = node.compatibleModules()
      if len(modules):
        relevant = QMenu()
        for modname in modules:
          module = self.loader.modules[modname]
          relevant.addAction(newAction(self, self.mainwindow,  modname, module.tags, module.icon))
        self.actionOpen.setMenu(relevant)


  def __exportToPdf(self):
    pdfFile = QtGui.QFileDialog.getSaveFileName(self, self.tr("Export to pdf file"),
                                                os.path.expanduser("~"),
                                                self.tr("Pdf files (*.pdf)"))
    if not pdfFile.endsWith(".pdf"):
      pdfFile.append(".pdf")
    self.__printer.setOutputFileName(pdfFile)
    self.__createPdf()


  def __createPdf(self):
    html = """
    <html>
    <head>
    <style type="text/css">
    img {
        max-width: 340px;
        max-height: 340px;
        width: expression(this.width > 340 ? "340px" : true);
        height: expression(this.height > 340 ? "340px" : true);
    }
    .break { page-break-before: always; }
    </style>
    </head>
    <body>
    """
    start = """<table style="height: 100%; margin: 1px auto; border-spacing: 10px; border-collapse: separate;">"""
    end  = """</table><p class="break"></p>"""
    count = 1
    row = ""
    for uid in self.checkedSelection._selection:
      cell = self.__nodeToHtmlCell(uid)
      if len(cell):
        row += cell
        if count == 1:
          html += start
        if count % 3 == 0:
          html += "<tr>\n{}\n</tr>".format(row)
          row = ""
        if count == 9:
          html += end
          count = 0
          row = ""
        count += 1
    if len(row):
      html += "<tr>{}</tr></table>".format(row)
    html += "</body></html>"
    self.document.setHtml(html)


  def __nodeToHtmlCell(self, uid):
    imagecell = """<td style="text-align: center;"><img src="data:image/jpg;base64,{}"/><br />{} {} {}</td>"""
    node = VFS.Get().getNodeById(uid)
    timestamp = ""
    device = ""
    model = ""
    make = ""
    b64image = self.__corrupt
    if node is not None:
      dtype = node.dataType()
      try:
        if dtype.find("image") != -1:
          vfile = node.open()
          image = vfile.read()
          vfile.close()
          data = node.attributesByName("exif.Model", ABSOLUTE_ATTR_NAME)
          if len(data):
            model = data[0].toString()
          data = node.attributesByName("exif.Make", ABSOLUTE_ATTR_NAME)
          if len(data):
            make = data[0].toString()
          if len(model) or len(make):
            device = "<br />{} {}".format(model, make)
          data = node.attributesByName("exif.DateTimeDigitized", ABSOLUTE_ATTR_NAME)
          if len(data):
            timestamp = "<br /> {}".format(data[0].toString())
          b64image = base64.b64encode(image)
      except:
        pass
      return imagecell.format(b64image, node.name(), device, timestamp)
    return ""


  def __print(self, ok):
    self.document.print_(self.__printer)


  def setOpenWith(self):
    owmenu = QMenu()
    setags = Utils.getSetTags()
    selist = list(setags)
    selist.sort()
    owmenu.addAction(self.mainwindow.actionBrowse_modules)
    owmenu.addSeparator()
    for tags in selist:
      if not tags == "builtins":
        action = QAction(QString(tags), self.mainwindow)
        menu = self.getMenuFromModuleTag(tags)
        action.setMenu(menu)
        owmenu.addAction(action)
    self.actionOpen_with.setMenu(owmenu)

  def getMenuFromModuleTag(self, tagname):
    menu = QMenu()
    modules = self.loader.modules
    for mod in modules :
      m = modules[mod]
      try :
        if m.tags == tagname:
          menu.addAction(newAction(self, self.mainwindow, mod, tagname, m.icon))
#            actions.append(newAction(self, self.__mainWindow, mod, self.tags, m.icon))
      except AttributeError, e:
        pass
    return menu

#####################################
#        CALLBACKS
#####################################
  def selectAll(self):
    self.model.selectAll()

  def openAsNewTab(self):
    node = self.model.currentNode()
    self.mainwindow.addNodeBrowser(node)

  def openParentFolder(self):
    node = self.model.currentNode()
    self.mainwindow.addNodeBrowser(node.parent(), node)

  def launchHexedit(self):
     node = self.model.currentNode()
     conf = self.loader.get_conf("hexadecimal")
     errnodes = ""
#     for node in nodes:
     if node.size():
       try:
         arg = conf.generate({"file": node})
         self.taskmanager.add("hexadecimal", arg, ["thread", "gui"])
       except RuntimeError:
         errnodes += node.absolute() + "\n"
     else:
       errnodes += node.absolute() + "\n"
     if len(errnodes):
       msg = QMessageBox(self)
       msg.setWindowTitle(self.tr("Empty files"))
       msg.setText(self.tr("the following nodes could not be opened with Hex viewer because they are either empty or folders\n"))
       msg.setIcon(QMessageBox.Warning)
       msg.setDetailedText(errnodes)
       msg.setStandardButtons(QMessageBox.Ok)
       ret = msg.exec_()

  def bookmark(self):
     self.bookManager.launch()

  def extractNodes(self):
     if len(self.model.selection.get()) == 0:
       nodes = [self.model.currentNode()]
     else:
       nodes = self.model.selection.getNodes()
     self.extractor.launch(nodes)


  def launchExtract(self):
     args = self.extractor.getArgs()
     conf = self.loader.get_conf("extract")
     try:
       margs = conf.generate(args)
       self.taskmanager.add("extract", margs, ["thread", "gui"])
     except RuntimeError as e:
       msg = QMessageBox(self)
       msg.setWindowTitle(self.tr("Extraction Error"))
       msg.setText(self.tr("An issue occured while extracting \n"))
       msg.setIcon(QMessageBox.Warning)
       msg.setDetailedText(str(e))
       msg.setStandardButtons(QMessageBox.Ok)
       ret = msg.exec_()

  def openDefault(self, node = None):
     if not node:
       node = self.model.currentNode()
     mods = node.compatibleModules()
     if len(mods):
       for mod in mods:
          if "Viewers" in self.lmodules[mod].tags:
	    break
       try:
         priority = modulePriority[mod]
       except KeyError:
         modulePriority[mod] = 0
         priority = 0
       if self.lmodules[mod]:
         conf = self.lmodules[mod].conf
         arguments = conf.arguments()
         marg = {}
         for argument in arguments:
           if argument.type() == typeId.Node:
             marg[argument.name()] = node
         args = conf.generate(marg)
	 if self.processusManager.exist(self.lmodules[mod], args):
	   mbox = QMessageBox(QMessageBox.Warning, self.tr("Module already applied"), self.tr("This module was already applied with the same configuration ! Do you want to apply it again ?"), QMessageBox.Yes | QMessageBox.No, self)
	   reply = mbox.exec_()
	   if reply == QMessageBox.No:
	      return
         else:
          if not priority: 
           mbox = QMessageBox(QMessageBox.Question, self.tr("Apply module"), self.tr("Do you want to apply module ") + str(mod) + self.tr(" on this node ?"), QMessageBox.Yes | QMessageBox.No, self)
           mbox.addButton(self.tr("Always"), QMessageBox.AcceptRole)
	   reply = mbox.exec_() 
           if reply == QMessageBox.No:
             return		
           elif reply == QMessageBox.AcceptRole:
	     modulePriority[mod] = 1 
         self.taskmanager.add(mod, args, ["thread", "gui"])       
	 return
     else:
       errnodes = ""
       if node.size():
         conf = self.lmodules["hexadecimal"].conf
         try:
           arg = conf.generate({"file": node})
           self.taskmanager.add("hexadecimal", arg, ["thread", "gui"])
         except RuntimeError:
           errnodes += node.absolute() + "\n"
       else:
         errnodes += node.absolute() + "\n"
       if len(errnodes):
         msg = QMessageBox(self)
         msg.setWindowTitle(self.tr("Empty files"))
         msg.setText(self.tr("the following nodes could not be opened with Hex viewer because they are either empty or folders\n"))
         msg.setIcon(QMessageBox.Warning)
         msg.setDetailedText(errnodes)
         msg.setStandardButtons(QMessageBox.Ok)
         ret = msg.exec_()


  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
#      self.mainwindow.changeEvent(event)
#      self.menuModule.setTitle(self.actionOpen_with.text())
#      self.submenuRelevant.setTitle(self.actionRelevant_module.text())
#      self.model.translation()
#      self.treeModel.translation()
    else:
      QWidget.changeEvent(self, event)

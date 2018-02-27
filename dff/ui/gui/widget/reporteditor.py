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
import os, sys
from distutils import sysconfig

from PyQt4.QtCore import Qt, SIGNAL, SLOT, pyqtSlot, QString, QUrl
from PyQt4.QtGui import QSplitter, QWidget, QVBoxLayout, QPushButton, QStackedWidget, QTextEdit, QTreeWidget, QMenu, QIcon, QAbstractItemView, QTreeWidgetItem, QDialog, QLineEdit, QApplication, QCursor, QInputDialog, QMessageBox, QIcon, QGroupBox, QComboBox
#from PyQt4.QtWebKit import QWebView

from dff.api.events.libevents import EventHandler
from dff.api.gui.thumbnail import Thumbnailer
from dff.api.report.manager import ReportManager
from dff.ui.gui.widget.reportexport import ReportExportDialog
from dff.ui.gui.widget.renderer import UrlRenderer

class ReportTreeItemMenu(QMenu):
  def __init__(self, parent):
     QMenu.__init__(self, parent)
     self.addAction(QIcon(":top.png"), "Move up", parent, SLOT("moveUpDocument()"))
     self.addAction(QIcon(":down.png"), "Move down", parent, SLOT("moveDownDocument()"))
     self.addAction(QIcon(":cancel.png"), "Delete", parent, SLOT("deleteDocument()"))

class ReportTreeNewItemMenu(QMenu):
  def __init__(self, parent):
     QMenu.__init__(self, parent)
     self.addAction(QIcon(":text"), "Add notes", parent, SLOT("addNotes()"))

class ReportPageItem(QTreeWidgetItem):
  def __init__(self, parent, page):
     QTreeWidgetItem.__init__(self, parent)
     self.__page = page
     self.setFlags(Qt.ItemIsUserCheckable| Qt.ItemIsSelectable | Qt.ItemIsEnabled)
     self.setText(0, QString.fromUtf8(self.__page.title()))
     if self.__page.selected():
       self.setCheckState(0, Qt.Checked)
     else:
       self.setCheckState(0, Qt.Unchecked)
 
  def setData(self, column, role, variant):
     if role == Qt.CheckStateRole:
       if variant == Qt.Checked:
         self.__page.selected(True)
       else:
         self.__page.selected(False)
     QTreeWidgetItem.setData(self, column, role, variant)
 
  def page(self):
     return self.__page

  def moveUp(self):
     self.__page.moveBefore()

  def moveDown(self):
     self.__page.moveAfter()

  def remove(self):
     self.__page.remove()

class ReportCategoryItem(QTreeWidgetItem):
  def __init__(self, parent, categoryName):
     QTreeWidgetItem.__init__(self, parent)
     self.__pageItems = []
     self.setFlags(Qt.ItemIsUserCheckable| Qt.ItemIsSelectable | Qt.ItemIsEnabled)
     self.__category = ReportManager().category(categoryName)
     self.setText(0, QString.fromUtf8(self.__category.name()))
     self.refreshPage()
     if self.__category.selected():
       self.setCheckState(0, Qt.Checked)
     else:
       self.setCheckState(0, Qt.Unchecked)

  def setData(self, column, role, variant):
     if role == Qt.CheckStateRole:
       if variant == Qt.Checked:
         self.__category.selected(True)
         for pageItem in self.__pageItems:
            pageItem.setCheckState(0, Qt.Checked)
       else:
         self.__category.selected(False)
         for pageItem in self.__pageItems:
           pageItem.setCheckState(0, Qt.Unchecked)
     QTreeWidgetItem.setData(self, column, role, variant)

  def pageItem(self, page):
     for pageItem in self.__pageItems:
        if pageItem.page() == page:
          return
     pageItem = ReportPageItem(self, page)
     self.__pageItems.append(pageItem)
     return pageItem

  def refreshPage(self):
     """Check if there is a new page to add, if then create it and return true"""
     if len(self.__pageItems) != len(self.__category):
       for page in self.__category:
         if self.pageItem(page):
           return True
     return False

  def category(self):
     return self.__category

  def moveUp(self):
     ReportManager().moveCategoryBefore(self.__category)

  def moveDown(self):
     ReportManager().moveCategoryAfter(self.__category)

  def remove(self):
     ReportManager().removeCategory(self.__category)

class ReportEditorTree(QTreeWidget):
  def __init__(self, parent):
     QTreeWidget.__init__(self)
     self.treeItemMenu = ReportTreeItemMenu(self)
     self.treeNewItemMenu = ReportTreeNewItemMenu(self)
     self.header().hide()
     self.connect(parent, SIGNAL("newCategory"), self.newCategory)
     self.connect(parent, SIGNAL("newPage"), self.newPage)
     self.connect(self, SIGNAL("itemClicked(QTreeWidgetItem*, int)"), self.clicked)
     self.thumbnailer = Thumbnailer()
     self.reportManager = ReportManager()
     self.__categoryItems = [] 

  def categoryItem(self, categoryName):
     for item in self.__categoryItems:
        if item.category().name() == categoryName:
           return item
     item = ReportCategoryItem(self, categoryName)
     self.__categoryItems.append(item)
     return item
 
  def removeCategoryItem(self, categoryItem):
     try :
       self.__categoryItems.remove(categoryItem)
     except ValueError:
       pass

  def newPage(self, categoryName):
     categoryName = categoryName.decode('UTF-8') #Variant didn't support unicode object so must decode from str
     for categoryItem in self.__categoryItems:
        if categoryName == categoryItem.category().name():
          categoryItem.refreshPage() 
 
  def newCategory(self, categoryName):
     categoryName = categoryName.decode('UTF-8')
     categoryItem = self.categoryItem(categoryName)

  def export(self):
     extractDialog = ReportExportDialog()
     extractDialog.export(exportContent = False, askOptions = True, checkExportSize = True)
 
  def mousePressEvent(self, e):
     QTreeWidget.mousePressEvent(self, e)
     index = self.indexAt(e.pos())
     if index.isValid():
       item = self.itemAt(e.pos())
       if e.button() == Qt.LeftButton:
           self.emit(SIGNAL("itemClicked"), item)
       elif e.button() == Qt.RightButton:
	 self.treeItemMenu.popup(QCursor.pos())
     else:
       if e.button() == Qt.RightButton:
	 self.treeNewItemMenu.popup(QCursor.pos()) 

  @pyqtSlot()
  def deleteDocument(self):
     item = self.currentItem()
     item.remove()
     item.takeChildren()
     parent = item.parent() 
     if parent:
       parent.removeChild(item)
     else:
       self.removeCategoryItem(item)
       index = self.indexOfTopLevelItem(item)
       self.takeTopLevelItem(index)

  @pyqtSlot()
  def moveUpDocument(self):
     item = self.currentItem()
     item.moveUp()
     parent = item.parent()
     if not parent:
       parent = self.invisibleRootItem()
     index = parent.indexOfChild(item)
     if index != 0:
       parent.takeChild(index)
       parent.insertChild(index - 1, item)
     self.setCurrentItem(item)

  @pyqtSlot()
  def moveDownDocument(self):
     item = self.currentItem()
     item.moveDown()
     parent = item.parent()
     if not parent:
       parent = self.invisibleRootItem()
     index = parent.indexOfChild(item)
     if (index + 1) != parent.childCount():
       parent.takeChild(index)
       parent.insertChild(index + 1, item)
     self.setCurrentItem(item)

  @pyqtSlot()
  def addNotes(self):
     noteName, ok = QInputDialog.getText(self, "New note", "Note name:", QLineEdit.Normal, "New note")
     if ok and noteName != "":
       item = self.currentItem()
       page = self.reportManager.createPage("Notes", unicode(noteName.toUtf8()))
       page.addText("Notes", "Enter your notes here ...")
       self.reportManager.addPage(page)

class ReportEditor(QSplitter, EventHandler):
  def __init__(self, parent, outputpath = None):
     QSplitter.__init__(self)
     EventHandler.__init__(self)
     self.reportManager = ReportManager()
     self.reportManager.connection(self)
     self.parent = parent
     self.name = self.tr("Report Editor")

     self.reportView = ReportEditorView(self)
     self.reportTree = ReportEditorTree(self)

     self.connect(self.reportTree, SIGNAL("itemClicked"), self.reportView.displayItem)
	
     treeWidget = QWidget() 
     vbox = QVBoxLayout()
     vbox.addWidget(self.reportTree)

     buttonPreview = QPushButton(self.tr("&Generate preview"), treeWidget)
     self.connect(buttonPreview, SIGNAL("clicked()"), self.reportView.showReportPreview)
     vbox.addWidget(buttonPreview)   

     buttonExport = QPushButton(self.tr("&Export"), treeWidget)
     self.connect(buttonExport, SIGNAL("clicked()"), self.reportTree.export)
     vbox.addWidget(buttonExport)
     treeWidget.setLayout(vbox)
     self.addWidget(treeWidget)	

     self.addWidget(self.reportView)
     self.setStretchFactor(1, 2)

  def Event(self, e):
     if e.type == ReportManager.EventNewCategory:
        self.emit(SIGNAL("newCategory"), e.value.value())

     if e.type == ReportManager.EventNewPage:
         self.parent.showReportEdit()
         self.emit(SIGNAL("newPage"), e.value.value())

class ReportWebView(QWebView):
  def __init__(self, parent):
    QWebView.__init__(self, parent)
 
  def contextMenuEvent(self, event):
    menu = self.page().createStandardContextMenu()
    for actionId in (1, 2, 3, 5, 8, 9, 10, 11):
      action = self.pageAction(actionId)
      action.setDisabled(True)
      menu.removeAction(action)
    if menu.isEmpty():
      menu.exec_(self.mapToGlobal(event.pos()))

class ReportEditorView(QStackedWidget):
  def __init__(self, parent):
     QStackedWidget.__init__(self, parent)
     vbox = QVBoxLayout()

     self.webView = ReportWebView(self)
     self.textWidget = QWidget(self)
     self.textEdit = QTextEdit(self)

     self.addWidget(self.webView)

     self.__saveState = True
     self.connect(self.textEdit, SIGNAL("textChanged()"), self.setUnsaved)

     vbox.addWidget(self.textEdit)
     self.buttonSaveNote = QPushButton("&Save note", self.textWidget)
     self.connect(self.buttonSaveNote, SIGNAL("clicked()"), self.saveNotes)
     vbox.addWidget(self.buttonSaveNote)
     self.textWidget.setLayout(vbox)
     self.addWidget(self.textWidget)

     self.buttonSaveNote.hide()
     self.urlRenderer = UrlRenderer(self)
     page = self.webView.page()
     page.setNetworkAccessManager(self.urlRenderer)
     page.setForwardUnsupportedContent(True)
     self.showReportPreview()

  def showReportPreview(self):
     QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
     m = ReportManager().exportPreview()
     self.urlRenderer.setPages(m)
     self.webView.settings().clearMemoryCaches()
     indexpage = os.path.join(ReportManager.TemplatePath, "index.html")
     # XXX patch for Windows platform
     #  if index.js is empty on Windows, doing alt-tab will crash DFF
     #  the following code check is index is empty or not. If empty
     #  line including injex.js in original index.html is removed in
     #  in the buffer. Then the buffer is provided to webView with setHtml.
     #  Replace self.webView.load(QUrl.fromLocalFile(indexpage))
     f = open(indexpage, 'r')
     buff = f.read()
     f.close()
     if len(ReportManager().index()) == 0:
       idx = buff.find('src="index.js"')
       creidx = buff.find("\n", idx)
       crsidx = buff[:creidx].rfind("\n")
       buff = buff[:crsidx] + buff[creidx:]
     self.webView.setHtml(buff, QUrl.fromLocalFile(indexpage))
     # XXX end of patch
     self.setCurrentWidget(self.webView)
     QApplication.restoreOverrideCursor()

  def displayItem(self, item):
     if self.currentWidget() == self.textWidget and self.saved() == False:
       if QMessageBox.warning(self, "Save note", "Do you want to save your note ?", QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
	 self.saveNotes()
         self.buttonSaveNote.hide()
    
     if isinstance(item, ReportPageItem):
       self.currentItem = item
       fragment = self.itemPageFragmentNotes(item)
       if fragment:
         self.buttonSaveNote.show()
         self.setCurrentWidget(self.textWidget)
         self.setTextHtml(fragment.data)
         self.setSaved()
         return

     if self.currentWidget() != self.webView:
       self.setCurrentWidget(self.webView)
        
  def itemPageFragmentNotes(self, item):
     for fragment in item.page().fragments:
        if fragment.title == "Notes":
          return fragment

  def setTextHtml(self, html):
     QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
     self.textEdit.setHtml(html)
     QApplication.restoreOverrideCursor()

  def saveNotes(self):
     fragment = self.itemPageFragmentNotes(self.currentItem)
     if fragment:
       fragment.data = unicode(self.textEdit.toPlainText().toUtf8())
     self.setSaved()

  def saved(self):
     return self.__saveState

  def setSaved(self):
     self.__saveState = True

  def setUnsaved(self):
     self.__saveState = False

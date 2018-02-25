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
from PyQt4.QtCore import Qt, SIGNAL, QString
from PyQt4.QtGui import QWidget, QDialog, QListWidgetItem, QColor, QMessageBox

from dff.api.vfs.libvfs import VFS, TagsManager
from dff.api.gui.dialog.tagedit import TagEditDialog
from dff.ui.gui.resources.ui_tags import Ui_Tags 

class TagItem(QListWidgetItem):
  def __init__(self, tag = None, count = None):
     QListWidgetItem.__init__(self)
     self.nodesCount = count 
     self.__tag = tag

  def tag(self):
     return self.__tag

  def setNodesCount(self, count):
     self.nodesCount = count

  def data(self, role):
     if role == Qt.DisplayRole:
       if self.nodesCount :
         return QString.fromUtf8(self.__tag.name() + ' (' + str(self.nodesCount) + ')')  
       else:
         return QString.fromUtf8(self.__tag.name())
     elif role == Qt.BackgroundRole:
	 color = self.__tag.color()
	 return QColor(color.r, color.g, color.b)
     return QListWidgetItem.data(self, role)
	
class TagManagerDialog(QDialog, Ui_Tags):
  def __init__(self, parent = None, selectedNodesList = []):
     QDialog.__init__(self, parent)
     self.setupUi(self)
     self.VFS = VFS.Get()
     self.connect(self.newTagButton, SIGNAL("clicked()"), self.editTag)   
     self.connect(self.deleteTagButton, SIGNAL("clicked()"), self.deleteTag)   
     self.connect(self.addTagNodesButton, SIGNAL("clicked()"), self.addTagNodes)   
     self.connect(self.removeTagNodesButton, SIGNAL("clicked()"), self.removeTagNodes)   
     self.connect(self.selectedTags, SIGNAL("itemDoubleClicked(QListWidgetItem*)"), self.editTag)
     self.connect(self.allTags, SIGNAL("itemDoubleClicked(QListWidgetItem*)"), self.editTag)
     self.tagsManager = TagsManager.get()
     if len(selectedNodesList) == 1 and selectedNodesList[0] == None:
       self.selectedNodesList = []
     else:
       self.selectedNodesList = selectedNodesList
     self.selectedNodes = []
     self.fillLists()
     self.translation()

  def translation(self):
     self.msgWarning = self.tr("Warning")
     self.msgNoNodes =  self.tr('No nodes was selected in the browser.')
     self.msgNoAllTags = self.tr("No tags was selected in the available tags list.")
     self.msgNoSelectedTags = self.tr("No tags was selected in the selected nodes tags list.")
     self.msgDefaultTag = self.tr("This is a default tag it cannot be deleted. All tagged VFS nodes was untagged.")
     self.msgDelete = self.tr("Are you sure ? This will delete this tag for all nodes in the VFS !")
 
  def listNodes(self):
     if len(self.selectedNodes):
       return self.selectedNodes
     if len(self.selectedNodesList):
       self.selectedNodes = self.selectedNodesList
     labelText = unicode(self.selectedLabel.text().toUtf8(), 'UTF-8')
     if labelText.find('(') == -1:
       text = labelText + ' (' + str(len(self.selectedNodes)) + ')'
       self.selectedLabel.setText(text)
     return self.selectedNodes
 
  def fillLists(self):
     self.fillAllTags()
     self.fillNodesTags()

  def fillNodesTags(self):
     nodes = self.listNodes()
     if len(nodes):
       dicSelectedTags = {}
       for node in nodes:
	  tags = node.tags()
          for tag in tags:
	    try:
	      dicSelectedTags[tag.id()] += 1
	    except KeyError:
	      dicSelectedTags[tag.id()] = 1 
       for tagId in dicSelectedTags:
	  tag = self.tagsManager.tag(tagId)
	  item = TagItem(tag, dicSelectedTags[tag.id()])
          self.selectedTags.addItem(item)

  def fillAllTags(self):
     tags = self.tagsManager.tags()
     for tag in tags:
        item = TagItem(tag)
        self.allTags.addItem(item)

  def accept(self):
     QDialog.accept(self)

  def findTagItem(self, listWidget, tagId):
     for i in xrange(0, listWidget.count()):
        if listWidget.item(i).tag().id() == tagId:
	  return listWidget.item(i) 
     return None

  def addTagNodes(self):
     currentItem = self.allTags.currentItem()
     if (currentItem):
       nodes = self.listNodes()
       tag = currentItem.tag()
       if len(nodes) == 0:
	 msgBox = QMessageBox(QMessageBox.Warning, self.msgWarning, self.msgNoNodes, QMessageBox.Ok, self)
	 msgBox.exec_()
	 return
       for node in nodes:
  	 node.setTag(tag.id())
       item = self.findTagItem(self.selectedTags, tag.id())
       if not item:
	 item = TagItem(tag, len(nodes))
         self.selectedTags.addItem(item)
       else:
	 item.setNodesCount(len(nodes))
     else:
	msgBox = QMessageBox(QMessageBox.Warning, self.msgWarning, self.msgNoAllTags, QMessageBox.Ok, self)
        msgBox.exec_()

  def removeTagNodes(self):
     currentItem = self.selectedTags.currentItem()
     if (currentItem):
       nodes = self.listNodes()
       tag = currentItem.tag()
       for node in nodes:
          node.removeTag(tag.id())
       row = self.selectedTags.row(currentItem)
       self.selectedTags.takeItem(row)
       del currentItem
     else:
       msgBox = QMessageBox(QMessageBox.Warning, self.msgWarning, self.msgNoSelectedTags, QMessageBox.Ok, self)
       msgBox.exec_()

  def editTag(self, item = None):
     if item:
       tag = item.tag()
     else:
       tag = None
     dialog = TagEditDialog(self, tag)
     if dialog.exec_():
       if not tag:
	  item = TagItem(self.tagsManager.tag(dialog.newTag))
	  self.allTags.addItem(item)

  def deleteTag(self):
     currentItem = self.allTags.currentItem()
     msgBox = QMessageBox(QMessageBox.Warning, self.msgWarning, self.msgDelete, QMessageBox.Yes | QMessageBox.No, self)
     button = msgBox.exec_()
     if button == QMessageBox.Yes:
       if currentItem:
         tag = currentItem.tag()
         if self.tagsManager.remove(tag.id()) != 0:
           row = self.allTags.row(currentItem)  
           self.allTags.takeItem(row)
           del currentItem
         else:
	   msgBox = QMessageBox(QMessageBox.Warning, self.msgWarning, self.msgDefaultTag, QMessageBox.Ok, self) 
	   msgBox.exec_()
         item = self.findTagItem(self.selectedTags, tag.id())
         if item:
           row = self.selectedTags.row(item)
           self.selectedTags.takeItem(row)
	   del item
       else:
	 msgBox = QMessageBox(QMessageBox.Warning, self.msgWarning, self.msgNoAllTags, QMessageBox.Ok, self)
	 msgBox.exec_()

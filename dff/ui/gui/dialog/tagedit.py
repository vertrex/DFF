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
from random import randint

from PyQt4.QtCore import Qt, QString, SIGNAL
from PyQt4.QtGui import QWidget, QDialog, QColorDialog, QListWidgetItem, QColor, QColorDialog, QPalette

from dff.api.vfs.libvfs import VFS, TagsManager
from dff.ui.gui.resources.ui_tagedit import Ui_edittag

class TagEditDialog(QDialog, Ui_edittag):
  def __init__(self, parent = None, tag = None):
     QDialog.__init__(self, parent)
     self.setupUi(self)
     self.VFS = VFS.Get()
     self.tagsManager = TagsManager.get()
     self.connect(self.setColorButton, SIGNAL("clicked()"), self.setColor)  
     self.connect(self.tagEdit, SIGNAL("editingFinished()"), self.setName)
     self.tag = tag
     if self.tag:
       self.tagColor = None
       self.tagName = None 
       self.fill(tag)
     else:
       self.tagName = unicode(self.tagEdit.text())
       self.tagColor = (randint(0, 255), randint(0, 255),  randint(0, 255))
       self.setEditColor(QColor(*self.tagColor))

  def fill(self, tag):
     self.setEditName(tag.name())
     color = tag.color()
     qcolor = QColor(color.r, color.g, color.b)  
     self.setEditColor(qcolor) 

  def setEditName(self, name):
     self.tagEdit.clear()
     self.tagEdit.insert(QString.fromUtf8(name))  

  def setEditColor(self, qcolor):
     palette = QPalette()
     palette.setColor(QPalette.Base, qcolor)
     self.tagEdit.setPalette(palette)

  def setName(self):
     self.tagName = self.tagEdit.text().toUtf8()

  def setColor(self):
     colorDialog = QColorDialog()
     if self.tag:
       color = self.tag.color()  	
       qcolor = colorDialog.getColor(QColor(color.r, color.g, color.b))
     else:
       qcolor = colorDialog.getColor()
     if qcolor.isValid():
       self.setEditColor(qcolor)
       self.tagColor = (qcolor.red(), qcolor.green(), qcolor.blue())

  def reject(self):
     QDialog.reject(self)

  def accept(self):
     if self.tag:
       if self.tagName or self.tagColor:
         if self.tagName:
	   self.tag.setName(unicode(self.tagName, 'UTF-8').encode('UTF-8'))
         if self.tagColor:
           self.tag.setColor(*self.tagColor)
         QDialog.accept(self)
         return
     else:
       try:
         self.newTag = self.tagsManager.add(unicode(self.tagName, 'UTF-8').encode('UTF-8'), *self.tagColor)
       except:
	 self.newTag = None
       QDialog.accept(self)
       return
     QDialog.reject(self)
     return

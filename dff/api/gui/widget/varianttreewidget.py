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
#  Frederic Baguelin <fba@digital-forensic.org>
#
from PyQt4.QtCore import Qt, QString, QEvent, SIGNAL, QSize
from PyQt4.QtGui import QTreeWidget, QTreeWidgetItem, QApplication, QLineEdit, QDialog, QDialogButtonBox, QLayout, QVBoxLayout, QHBoxLayout, QLabel, QStyle, QPixmap, QSizePolicy, QFontMetrics, QMenu, QCursor, QClipboard

from dff.api.types.libtypes import typeId
from dff.api.vfs.vfs import vfs

from dff.ui.gui.resources.ui_varianttreewidget import Ui_VariantTreeWidget

class VariantTreeWidget(QTreeWidget, Ui_VariantTreeWidget):
    def __init__(self, parent=None):
        QTreeWidget.__init__(self, parent)
        self.setupUi(self)
        self.connect(self, SIGNAL("itemDoubleClicked(QTreeWidgetItem*, int)"), self.displayItem)
        self.copyMenu = AttributeCopyMenu(self) 
        self.mainwindow = QApplication.instance().mainWindow

    def setItemText(self, item, vval):
        if vval == None:
	    item.setText(1, str("None")) 
        elif vval.type() == typeId.DateTime:
            dateTime = vval.value()
	    if dateTime:
              item.setText(1, str(dateTime))
        elif vval.type() in [typeId.Int16, typeId.UInt16, typeId.Int32, typeId.UInt32, typeId.Int64, typeId.UInt64]:
            item.setText(1, vval.toString() + " - " + vval.toHexString())
        elif vval.type() in [typeId.Char, typeId.String, typeId.CArray]:
            val = vval.toString()
            item.setText(1, QString.fromUtf8(val))
        elif vval.type() == typeId.Node:
            label = QLabel('<a href="' + QString.fromUtf8(vval.value().path()) + '" style="color: blue">'+ QString.fromUtf8(vval.value().absolute()) + ' </a>')
            label.connect(label, SIGNAL("linkActivated(QString)"), self.gotolink)
            self.setItemWidget(item, 1, label)
        elif vval.type() == typeId.Path:
            item.setText(1, QString.fromUtf8(vval.value().path))
        else:
            item.setText(1, str(vval.value()))
        
    def fillMap(self, parent, vmap):
        for key in vmap.iterkeys():
            item = QTreeWidgetItem(parent)
            item.setText(0, QString.fromUtf8(key))
            vval = vmap[key]
            expand = True
	    if vval == None:
	      self.setItemText(item, vval)	
            elif vval.type() == typeId.Map:
                vvmap = vval.value()
                self.fillMap(item, vvmap)
            elif vval.type() == typeId.List:
                vlist = vval.value()
                size = len(vlist)
                if size > 30:
                    expand = False
                item.setText(1, "total items (" + str(size) + ")")
                self.fillList(item, vlist)
            else:
                self.setItemText(item, vval)
            if expand:
                self.expandItem(item)


    def fillList(self, parent, vlist):
        for vval in vlist:
            if vval.type() == typeId.Map:
                vmap = vval.value()
                self.fillMap(parent, vmap)
            elif vval.type() == typeId.List:
                vvlist = vval.value()
                self.fillList(parent, vvlist)
            else:
                item = QTreeWidgetItem(parent)
                self.setItemText(item, vval)

    def itemAttributeValue(self, item):
	message = QString()
        it = 0
	itemPath = ""
	currentItem = item.parent()
	while currentItem and currentItem.text(0) != "attributes":
	   itemPath = currentItem.text(0) + '.' + itemPath
	   currentItem = currentItem.parent()
	itemPath += item.text(0)
	return (itemPath, item.text(1))

    def displayItem(self, item, col):
	attribute, value = self.itemAttributeValue(item)
	dialog = ItemValueDialog(self, attribute, value)
	dialog.exec_() 

    def gotolink(self, path):
      if path:
	p = str(path.toUtf8())
        v = vfs()
        n = v.getnode(str(path.toUtf8()))
        self.mainwindow.addNodeBrowser(rootpath=n)

    def copyToClipboard(self):
 	clipboard = QApplication.clipboard()		
	item = self.currentItem()
        column = self.currentColumn()
	attribute, value = self.itemAttributeValue(item)
	if column == 0:
	  clipboard.setText(attribute, QClipboard.Clipboard)
	  clipboard.setText(attribute, QClipboard.Selection)
	else:
	  clipboard.setText(value, QClipboard.Clipboard) 
	  clipboard.setText(value, QClipboard.Selection) 

    def mousePressEvent(self, event):
        index = self.indexAt(event.pos())
        if index.isValid():
	  item = self.itemAt(event.pos())
	  if event.button() == Qt.RightButton:
	    self.copyMenu.popup(QCursor.pos())
	QTreeWidget.mousePressEvent(self, event)

    def changeEvent(self, event):
        """ Search for a language change event
        
        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
        else:
            QTreeWidget.changeEvent(self, event)


class AttributeCopyMenu(QMenu):
  def __init__(self, parent):
     QMenu.__init__(self, parent)
     action = self.addAction(self.tr("copy"))
     self.connect(action, SIGNAL("triggered()"), parent.copyToClipboard)

class ItemLineEdit(QLineEdit):
  def __init__(self, text):
     QLineEdit.__init__(self, text)
     self.setFrame(False)
     self.setReadOnly(True)
     
  def sizeHint(self):
     fm = QFontMetrics(self.font())
     h = fm.height()
     w = fm.width(self.displayText()) + (fm.width(' ') * 2)
     return QSize(w, h)

class ItemValueDialog(QDialog):
  def __init__(self, parent, path, value):
    QDialog.__init__(self)
    self.setWindowTitle(self.tr("Attribute value"))
    vlayout = QVBoxLayout()
    hlayout = QHBoxLayout()

    label = QLabel()
    label.setPixmap(self.style().standardIcon(QStyle.SP_MessageBoxInformation).pixmap(32, 32))
    hlayout.addWidget(label)

    button = QDialogButtonBox(QDialogButtonBox.Ok)
    self.connect(button, SIGNAL('accepted()'), self.accept)	


    attributeLayout = QHBoxLayout()
    attributeLabel = QLabel(self.tr("Attribute") + ":")
    linePath = ItemLineEdit(path)
    attributeLayout.addWidget(attributeLabel)
    attributeLayout.addWidget(linePath)
    attributeLayout.setSizeConstraint(QLayout.SetFixedSize)
    vlayout.addLayout(attributeLayout)

    if value:
      valueLayout = QHBoxLayout()
      valueLabel = QLabel(self.tr("Value" + ":"))
      lineValue = ItemLineEdit(value)
      valueLayout.addWidget(valueLabel)
      valueLayout.addWidget(lineValue)
      valueLayout.setSizeConstraint(QLayout.SetFixedSize)
      vlayout.addLayout(valueLayout)

    vlayout.addWidget(button)
    hlayout.addLayout(vlayout)
    self.setLayout(hlayout)
    self.setFixedHeight(self.sizeHint().height())

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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 
import os

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import SIGNAL, QString, Qt, QByteArray
from PyQt4.QtGui import QTableWidget, QHeaderView, QTableWidgetItem, QAbstractItemView, QMenu, QAction

from dff.modules.winreg.regtype import regtype
from dff.modules.winreg.decoders import DateDecoder, Rot13decoder, UserAssistDecoder, UTF16LEDecoder, UTF16BEDecoder

DECODER = {0: "Date",
           1: "Rot13",
           2: "UserAssist",
           3: "Default",
           4: "UTF16-LE",
           5: "UTF16-BE"
           }

class TableValue(QTableWidget):
  def __init__(self, model, parent = None):
    super(QTableWidget, self).__init__(parent)
    self.parent = parent
    self.configure()
    self.model = model
    self.connect(self.model, SIGNAL("keySelected"), self.updateTable)
    self.createDecoderMenu()

  def configure(self):
    self.setColumnCount(3)
    self.setRowCount(0)
    self.setAlternatingRowColors(True)
    self.setSelectionBehavior(QAbstractItemView.SelectRows)
    self.horizontalHeader().setResizeMode(1, QHeaderView.ResizeToContents)
    self.horizontalHeader().setResizeMode(2, QHeaderView.ResizeToContents)
    self.horizontalHeader().setResizeMode(3, QHeaderView.Stretch)
    self.horizontalHeader().setStretchLastSection(True)
    self.setShowGrid(True)
    self.verticalHeader().hide()
    self.setHorizontalHeaderLabels(("Name", "Type", "Data"))

  def resetTable(self):
      rows = self.rowCount()
      if rows > 0:
          while rows >= 0:
              self.removeRow(rows)
              rows = rows - 1

  def updateTable(self, rhive, key):
      self.resetTable()
      values = key.values
      for value in values:
          currow = self.rowCount()
          self.setRowCount(self.rowCount() + 1)
          if value.name:
            name = value.name
          else:
            name = "(Default)"
#          item_name = valueItem(value.fetch_data(), key.name)


#          item_name = QTableWidgetItem(QString.fromUtf8(name))
#          item_name.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
          item_name = valueItem(name, key.name)

          item_type = QTableWidgetItem(QString(regtype[value.type]))
          item_type.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
 
          item_data = valueItem(value.fetch_data(), key.name)
#QTableWidgetItem(self.dataToQString(value.fetch_data()))
#          item_data.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
          self.setItem(currow, 0, item_name)
          self.setItem(currow, 1, item_type)
          self.setItem(currow, 2, item_data)
      del(rhive)

  def createDecoderMenu(self):
    self.menu = QMenu()
    for decid, decname in DECODER.iteritems():
      action = QAction(QString(decname), self.menu)
      self.menu.addAction(action)
    self.connect(self.menu, SIGNAL("triggered(QAction*)"), self.menuTriggered)
#    return menu

  def menuTriggered(self, action):
#    print "MENUUUU", action.text()
    try:
      item = self.currentItem().decode(action.text())
    except:
      pass
#    print "Cur"
    
  def mousePressEvent(self, event):
    item = self.itemAt(event.pos())
    if item != None:
      if event.button() == Qt.RightButton:
#      print item.text()
        self.setCurrentItem(item)
        self.menu.popup(event.globalPos())
      else:
        self.setCurrentItem(item)
#    option = QStyleOptionButton()
#    option.rect = QRect(3,2,20,20)
#    element = self.style().subElementRect(QStyle.SE_CheckBoxIndicator, option)
#    if element.contains(event.pos()):
#      if self.isOn:
#        self.isOn = False
#        self.emit(SIGNAL("headerSelectionClicked"), False)
#      else:
#        self.emit(SIGNAL("headerSelectionClicked"), True)
#        self.isOn = True
#        self.update()
#        self.headerDataChanged(Qt.Horizontal, 0, 0)
#    else:
#      index = self.logicalIndexAt(event.pos())
#      if self.cursor().shape() != Qt.SplitHCursor:
#                self.view.headerClicked(index)
#        QHeaderView.mousePressEvent(self, event)

class valueItem(QTableWidgetItem):
  def __init__(self, data, keyname):
    QTableWidgetItem.__init__(self)
    self.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
    self.data = data
    self.keyname = keyname

    self.setText(self.dataToQString(self.data))

  def dataToQString(self, data):
#     if keyInfo.valueDataDecoder():
#       if type(data) == bytearray and len(data):
#            data = QString.fromUtf8(keyInfo.valueDataDecode(data, keyName).decode())
#       elif type(data) == long or type(data) == int:
#            data = QString.fromUtf8(keyInfo.valueDataDecode(data, keyName).decode())
     if type(data) == bytearray:
       data = QByteArray(data).toHex()
     if type(data) == long:
         data = str(data)  
     if type(data) == int:
       data = str(data)
     if type(data) == list:
       d = unicode()
       for t in data:
         d += t
         d += ", "
       data = d
     elif data == None:
         data = 'None'
     return QString.fromUtf8(data)

  def decode(self, decodername):
    if decodername == "Default":
      self.setText(self.dataToQString(self.data))
    elif decodername == "Date":
      self.setText(QString(DateDecoder(self.data).decode()))
    elif decodername == "Rot13":
      self.setText(QString(Rot13decoder(self.data).decode()))
    elif decodername == "UserAssist":
      self.setText(QString(UserAssistDecoder(self.data, self.keyname).decode()))
    elif decodername == "UTF16-LE":
      self.setText(QString(UTF16LEDecoder(self.data).decode()))
    elif decodername == "UTF16-BE":
      self.setText(QString(UTF16BEDecoder(self.data).decode()))
    else:
      self.setText(self.dataToQString(self.data.encode("UTF8")))

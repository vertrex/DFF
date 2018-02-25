# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
# 
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

from PyQt4.QtCore import QString, Qt, SIGNAL
from PyQt4.QtGui import QWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QApplication, QHBoxLayout, QToolButton, QIcon, QToolBar, QAction, QDialog, QLineEdit, QLabel, QGridLayout, QDialogButtonBox, QLineEdit, QPixmap

class bookmark(QWidget):
    def __init__(self, parent):
        QWidget.__init__(self)
        self.init(parent)
        self.initShape()

    def init(self, parent):
        self.heditor = parent
        self.items = []

        self.selectedItem = -1

    def initShape(self):
        self.vbox = QVBoxLayout()
        self.vbox.setSpacing(0)

        self.dialog = bookDiag(self)

        self.initFunctions()
        self.initTree()
        self.setLayout(self.vbox)

    def initFunctions(self):
        self.booktool = QToolBar()
        self.booktool.setObjectName("Hexedit bookmark toolbar")

        self.add = QAction(QIcon(":bookmark_add.png"),  "Add bookmark",  self.booktool)
        self.booktool.addAction(self.add)

        self.rm = QAction(QIcon(":bookmark_rm.png"),  "Remove bookmark",  self.booktool)
        self.booktool.addAction(self.rm)

        self.edit = QAction(QIcon(":bookmark_toolbar.png"),  "Edit bookmark",  self.booktool)
        self.booktool.addAction(self.edit)

        #Callbacks

        self.add.connect(self.add, SIGNAL("triggered()"), self.addbook)
        self.rm.connect(self.rm, SIGNAL("triggered()"), self.rmbook)
        self.edit.connect(self.edit, SIGNAL("triggered()"), self.editbook)
        
        self.vbox.addWidget(self.booktool)
        
    def initTree(self):
        self.tree = QTreeWidget()
        self.tree.setColumnCount(5)
        
        headerLabels = [QApplication.translate("bookmark", "Address", None, QApplication.UnicodeUTF8),
                       QApplication.translate("bookmark", "Length (dec)", None, QApplication.UnicodeUTF8),
                       QApplication.translate("bookmark", "Length (hex)", None, QApplication.UnicodeUTF8),
                       QApplication.translate("bookmark", "Hex value", None, QApplication.UnicodeUTF8),
                       QApplication.translate("bookmark", "Ascii value", None, QApplication.UnicodeUTF8),
                        QApplication.translate("bookmark", "Description", None, QApplication.UnicodeUTF8)]
        
        self.tree.setHeaderLabels(headerLabels)
        self.tree.setAlternatingRowColors(True)
        
        self.connect(self.tree, SIGNAL("itemClicked(QTreeWidgetItem*,int)"), self.treeClicked)
        self.connect(self.tree, SIGNAL("itemDoubleClicked(QTreeWidgetItem*,int)"), self.treeDoubleClicked)
        self.vbox.addWidget(self.tree)

    #CALLBACKS

    def treeClicked(self, item, col):
        self.selectedItem = item

    def treeDoubleClicked(self, item, col):
        self.selectedItem = item
        add = QString(item.text(0))
        off = add.toULongLong(16)
        if off[1]:
            self.heditor.readOffset(off[0])
#            self.heditor.selection.offset = off[0]
#            self.heditor.whex.hexcursor.update()
#            self.heditor.whex.asciicursor.update()

    def getSelectedItemRow(self, address):
        cp = 0
        for item in self.items:
            if item.text(0) == address:
                return cp
            cp += 1
        return -1


    def addbook(self):
        self.dialog.setInformations()
        ret = self.dialog.exec_()
        if ret == 1:
            #XXXCheck if offsetis present
            item = QTreeWidgetItem(self.tree)
            address = self.dialog.address.text()
            declen = self.dialog.lendec.text()
            hexlen = self.dialog.lenhex.text()
            hexval = self.dialog.hexvalue.text()
            asciival = self.dialog.asciivalue.text()
            description = self.dialog.description.text()

            item.setText(0, address)
            item.setText(1, declen)
            item.setText(2, hexlen)
            item.setText(3, hexval)
            item.setText(4, asciival)
            item.setText(5, description)
            self.items.append(item)

    def rmbook(self):
        if (self.selectedItem != -1) and len(self.items) > 0:
            row = self.getSelectedItemRow(self.selectedItem.text(0))
            self.tree.takeTopLevelItem(row)
            self.items.remove(self.selectedItem)
            if len(self.items) > 0:
                if len(self.items) > row:
                    self.selectedItem = self.items[row]
                else:
                    self.selectedItem = self.items[row - 1]

    def editbook(self):
        print "edit"


class bookDiag(QDialog):
    def __init__(self, parent):
        QDialog.__init__(self)
        self.setWindowTitle("Add bookmark entry")
        self.init(parent)
        self.initShape()

    def init(self, parent):
        self.bookmark = parent
        self.heditor = self.bookmark.heditor

    def createButtons(self):
        self.buttonbox = QDialogButtonBox()
        self.buttonbox.setStandardButtons(QDialogButtonBox.Cancel|QDialogButtonBox.Ok)
        self.connect(self.buttonbox, SIGNAL("accepted()"),self.accept)
        self.connect(self.buttonbox, SIGNAL("rejected()"),self.reject)
        return self.buttonbox

    def initShape(self):
        self.grid = QGridLayout()

        decoration = self.createDecoration()
        wButton = self.createButtons()
        wInfos = self.createInformations()

        self.grid.addWidget(decoration, 0, 0)
        self.grid.addWidget(wInfos, 1, 0)
        self.grid.addWidget(wButton, 2, 0)

        self.setLayout(self.grid)

    def createDecoration(self):
        self.deco = QWidget()
        self.hdeco = QHBoxLayout()

        pixlabel = QLabel()
        pix = QPixmap(":bookmark.png")
        pixlabel.setPixmap(pix)

        booklabel = QLabel("Add a description to this entry")

        self.hdeco.addWidget(pixlabel)
        self.hdeco.addWidget(booklabel)

        self.deco.setLayout(self.hdeco)
        return self.deco

    def createInformations(self):
        self.info = QWidget()
        self.igrid = QGridLayout()

        addressLabel = QLabel("Address: ")
        self.address = QLineEdit()
        self.address.setReadOnly(True)

        lend = QLabel("Length (dec): ")
        self.lendec = QLineEdit()
        self.lendec.setReadOnly(True)

        lenh = QLabel("Length (hex): ")
        self.lenhex = QLineEdit()
        self.lenhex.setReadOnly(True)

        deslabel = QLabel("Description: ")
        self.description = QLineEdit()

        hvlabel = QLabel("Hex value:")
        self.hexvalue = QLineEdit()
        self.hexvalue.setReadOnly(True)

        avlabel = QLabel("Ascii value:")
        self.asciivalue = QLineEdit()
        self.asciivalue.setReadOnly(True)
        
        self.igrid.addWidget(addressLabel, 0, 0, Qt.AlignLeft)
        self.igrid.addWidget(self.address, 0, 1, Qt.AlignLeft)

        self.igrid.addWidget(lend, 1, 0, Qt.AlignLeft)
        self.igrid.addWidget(self.lendec, 1, 1, Qt.AlignLeft)

        self.igrid.addWidget(lenh, 2, 0, Qt.AlignLeft)
        self.igrid.addWidget(self.lenhex, 2, 1, Qt.AlignLeft)

        self.igrid.addWidget(hvlabel, 3, 0, Qt.AlignLeft)
        self.igrid.addWidget(self.hexvalue, 3, 1, Qt.AlignLeft)

        self.igrid.addWidget(avlabel, 4, 0, Qt.AlignLeft)
        self.igrid.addWidget(self.asciivalue, 4, 1, Qt.AlignLeft)


        self.igrid.addWidget(deslabel, 5, 0, Qt.AlignLeft)
        self.igrid.addWidget(self.description, 5, 1, Qt.AlignLeft)

        self.info.setLayout(self.igrid)

        return self.info

    def cleanInformations(self):
        self.address.clear()
        self.lendec.clear()
        self.lenhex.clear()
        self.hexvalue.clear()
        self.asciivalue.clear()
        self.description.clear()

    def setInformations(self):
        self.cleanInformations()

        if self.heditor.decimalview:
            add = "%.2d" % self.heditor.selection.startoffset
        else:
            add = "0x"
            add += "%.2x" % self.heditor.selection.startoffset
        self.address.insert(add)

        if self.heditor.selection.length > 0:
            len = self.heditor.selection.length
        else:
            len = 1
        tolendec = "%.1d" % len
        self.lendec.insert(tolendec)

        tolenhex = "0x"
        tolenhex += "%.1X" % len
        self.lenhex.insert(tolenhex)

        hval = self.heditor.readHexValue(self.heditor.selection.offset, len)
        self.hexvalue.insert(hval)

        aval = self.heditor.readAsciiValue(self.heditor.selection.offset, len)
        self.asciivalue.insert(aval)

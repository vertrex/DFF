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
from PyQt4.QtGui import QWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QApplication, QHBoxLayout, QToolButton, QIcon, QToolBar, QAction, QDialog, QLineEdit, QLabel, QGridLayout, QDialogButtonBox, QLineEdit, QPixmap, QTextEdit

from dff.api.exceptions.libexceptions import *

from dff.modules.hexedit.lfscrollbar import *

class stringView(QWidget):
    def __init__(self, parent):
        QWidget.__init__(self)
        self.init(parent)
        self.initShape()

        self.readBuffer(0)

    def init(self, parent):
        self.heditor = parent
        self.file = self.heditor.file
        #test
        self.readsize = self.heditor.pageSize * 5

        self.stringoffset = 0

    def initShape(self):
        self.hbox = QHBoxLayout()

        self.stringedit = QTextEdit()
        self.stringedit.setReadOnly(True)
        self.stringedit.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.scrollbar = stringLFScrollBar(self.heditor.filesize, self.heditor.pageSize, self.heditor.bytesPerLine, self)
        
        self.hbox.addWidget(self.stringedit)
        self.hbox.addWidget(self.scrollbar)

        self.setLayout(self.hbox)


    def readBuffer(self, offset):
        try:
            self.file.seek(offset)
            buff = self.file.read(self.readsize)
            stri = self.processBuffer(buff)
            self.printBuffer(stri)
        except vfsError, e:
            print e.error

    # get only strings and return stringified buffer
    def processBuffer(self, buff):
        printer = QString()

        for char in buff:
            if (char > "\x20" and char < "\x7e") or (self.isMetaChar(char)):
                printer.append(char)
        return printer

    def isMetaChar(self, char):
        if char == "\x0a":
            return True
        elif char == "\x09":
            return True
        else:
            return False

    def printBuffer(self, stri):
        #print stri
        self.stringedit.clear()
        self.stringedit.insertPlainText(stri)
        

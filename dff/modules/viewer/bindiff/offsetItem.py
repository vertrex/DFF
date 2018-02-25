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
import binascii
import struct
import string
import time

from PyQt4.QtCore import QString, Qt
from PyQt4.QtGui import QWidget, QFont, QColor, QTextCursor, QGraphicsTextItem

class offsetItem(QGraphicsTextItem):
    def __init__(self, whex):
        QGraphicsTextItem.__init__(self)
        self.initValues(whex)
#        self.initShape()
        self.initPosition()
        self.initFont()

    def initPosition(self):
        self.setPos(0, 25)

    def initValues(self, whex):
        self.whex = whex
        self.bdiff = self.whex.bdiff
        #Buffer
        self.buffer = []
        self.bufferLines = 0 
        #Line
        self.currentLine = 0
        #Offset
        self.startOffset = 0
        self.fontPixel = 14

    def initFont(self):
        self.setDefaultTextColor(QColor(Qt.red))

        self.font = QFont("Gothic")
        self.font.setFixedPitch(1)
        self.font.setBold(False)
        self.font.setPixelSize(self.fontPixel)
        self.setFont(self.font)

    #Print Operations
    def printFullOffset(self, start, len):
        count = 0
        fullBuff = QString()

        while count <= len:
            if self.bdiff.opt_offsetBase == 1:
                fullBuff.append("%.10d" % start)
            elif self.bdiff.opt_offsetBase == 0:
                fullBuff.append("%.10X" % start)
            fullBuff.append("\n")
            start += 16
            count += 1

        #Clear and set
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.Start)
        cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
        self.setPlainText(fullBuff)
        cursor.movePosition(QTextCursor.Start)

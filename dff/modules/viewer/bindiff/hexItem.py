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
import binascii
import struct
import string
import time

from PyQt4.QtCore import QString, Qt,  QRegExp
from PyQt4.QtGui import QWidget, QFont, QColor, QTextCursor, QGraphicsTextItem, QFontMetrics, QTextDocument, QSyntaxHighlighter, QTextCharFormat, QBrush

#from cursors import hexCursor

class hexItem(QGraphicsTextItem):
    def __init__(self, whex):
        QGraphicsTextItem.__init__(self)
        self.initValues(whex)
        self.initPosition()
        self.initFont()
        self.initMetricsValues()

    def initPosition(self):
        self.setPos(95, 25)

    def initValues(self, whex):
        self.whex = whex
        self.bdiff = self.whex.bdiff
        self.hexview = self.whex.view
        #Buffer
        self.buffer = []
        self.fontPixel = 14
        #Current Position

        self.bytesPerLine = self.bdiff.bytesPerLine
        self.groupBytes = self.bdiff.groupBytes

        #Selection
        self.select = False
        self.xsel = 0
        self.ysel = 0

    def initDocument(self):
        self.document = QTextDocument()
        self.setDocument(self.document)

    def initFont(self):
        self.setDefaultTextColor(QColor(Qt.black))

        self.font = QFont("Gothic")
        self.font.setFixedPitch(1)
        self.font.setBold(False)
        self.font.setPixelSize(self.fontPixel)
#        self.setFont(self.font)
        self.setFont(self.font)

        #Search Highlight font
        self.sfont = QFont("Gothic")
        self.sfont.setFixedPitch(1)
        self.sfont.setBold(False)
        self.sfont.setPixelSize(self.fontPixel)

        self.metric = QFontMetrics(self.font)

    def initMetricsValues(self):
        #Calibrate
        calibrate = QString("A")
        self.charsByByte = 2 * self.groupBytes
        self.charW = self.metric.width(calibrate)
        self.charH = self.metric.height()

        self.byteW = self.charW * self.charsByByte
        self.byteH = self.charH

    def initStartBlank(self):
        self.lineW = self.boundingRect().width()
        self.startBlank = self.lineW - (self.byteW * self.bytesPerLine) - (self.charW * (self.bytesPerLine - 1))

    #Print Operations

    def dumpHexBuffer(self, buff):
        self.printFullBuffer(buff)

    def dumpEOF(self):
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.Start)
        cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
        self.setPlainText("\t\tEnd of file")
        cursor.movePosition(QTextCursor.Start)

            
    def printFullBuffer(self, buff):
        del self.buffer
        pos = str(len(buff)) + 'B'
        self.buffer = struct.unpack(pos, buff)
        count = 0
        fullBuff = QString()
        for byte in self.buffer:
            fullBuff.append("%.2x" % byte)
            if count < 15:
                fullBuff.append(" ")
                count += 1
            else:
                fullBuff.append("\n")
                count = 0

        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.Start)
        cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
        self.setPlainText(fullBuff)
        cursor.movePosition(QTextCursor.Start)

    def colorizeDiff(self, diffinfos):
        cursor = self.textCursor()
        cursor.setPosition(QTextCursor.Start)

        text = self.toPlainText()

        keys = diffinfos.keys()
        keys.sort()
        for offset in keys:
            difflen = diffinfos[offset]
            pos = (offset * 2) + offset
            count = difflen + (((offset + difflen) / 16) - (offset / 16))

            cursor.setPosition(pos, QTextCursor.MoveAnchor)
            cursor.movePosition(QTextCursor.NextWord, QTextCursor.KeepAnchor, count)

            format = QTextCharFormat()
            format.setFont(self.sfont)
            format.setForeground(QBrush(QColor(Qt.red)))
            cursor.setCharFormat(format)
            cursor.setPosition(QTextCursor.Start, QTextCursor.MoveAnchor)




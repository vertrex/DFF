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

from cursors import hexCursor

class hexItem(QGraphicsTextItem):
    def __init__(self, whex):
        QGraphicsTextItem.__init__(self)
        self.initValues(whex)
        self.initPosition()
#        self.initDocument()
        self.initFont()
        self.initMetricsValues()
#        self.initCursor()

    def initPosition(self):
        self.setPos(95, 25)

    def initValues(self, whex):
        self.whex = whex
        self.heditor = self.whex.heditor
        self.hexview = self.whex.view
        #Buffer
        self.buffer = []
        self.fontPixel = 14
        #Current Position

        self.bytesPerLine = self.heditor.bytesPerLine
        self.groupBytes = self.heditor.groupBytes

        #Selection
        self.select = False
        self.xsel = 0
        self.ysel = 0

    def initDocument(self):
        self.document = QTextDocument()
        self.setDocument(self.document)

#    def initSyntaxHighlighter(self):
#        self.search = self.heditor.right.search
#        self.highlighter = highlighter(self)

#    def initCursor(self):
#        self.cursor = hexCursor(self)
#        self.heditor.whex.view.scene.addItem(self.cursor)
 
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
#        print "start blank"
#        print self.startBlank

#    def getPatternOffsets(self, buff):
#       plist = self.search.searchedPatterns
#        startoffset = self.heditor.currentOffset
#        offlist = {}

#        for pattern, offsetlist  in plist.iteritems():
#            for offset in offsetlist:
#                if offset >= startoffset and offset <= startoffset + self.heditor.readSize:
#                    offlist[offset - self.heditor.currentOffset] = len(pattern) / 2
#        return offlist

    #Print Operations

    def dumpHexBuffer(self, buff):
        self.printFullBuffer(buff)
#        searchofflist = self.getPatternOffsets(buff)
#        if len(searchofflist) > 0:
#            highoffsets = searchofflist.keys()
#            highoffsets.sort()
#            self.highlighter(searchofflist)
            
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
#        if len(self.search.searchedPatterns) > 0:
#            self.highlighter.highlightBlock(self.document.toPlainText())

    def getXPos(self, x):
        count = 0
        current = self.byteW + (self.charW / 2) + (self.startBlank / 2)
        while current < x:
            count += 1
            current = current + self.byteW + self.charW
        return count

    def getYPos(self, y):
        count = 0
        current = self.byteH
        while current < y:
            count += 1
            current = current + self.byteH
        return count

    def highlighter(self, searchofflist):
        offsets = searchofflist.keys()
        cursor = self.textCursor()
        cursor.setPosition(QTextCursor.Start)
        for offset in offsets:
            len = searchofflist[offset]
            pos = (offset * 2) + offset
            cursor.setPosition(pos, QTextCursor.MoveAnchor)
            l = 0
            while l < len:
                cursor.movePosition(QTextCursor.NextWord, QTextCursor.KeepAnchor)
                l += 1

            format = QTextCharFormat()
            format.setFont(self.sfont)
            format.setForeground(QBrush(QColor(Qt.red)))
            cursor.setCharFormat(format)
            cursor.setPosition(QTextCursor.Start, QTextCursor.MoveAnchor)



    ############## #
    # MOUSE EVENTS # ###########################
    ############## #

    def mouseMoveEvent(self, event):
        pos = event.pos()
        x = pos.x()
        y = pos.y()
        xpos = self.getXPos(x)
        ypos = self.getYPos(y)
        self.heditor.selection.select(self.heditor.selection.xstart, self.heditor.selection.ystart, xpos, ypos)
	if not self.heditor.preview:
          self.heditor.infos.update()
          self.heditor.right.decode.update()

    def mousePressEvent(self, event):
        button = event.button()
        pos = event.pos()
        if event.button() == 1:
            #Get CLicked coordonates
            x = pos.x()
            y = pos.y()
            xpos = self.getXPos(x)
            ypos = self.getYPos(y)
            #refresh cursors
            self.whex.hexcursor.draw(xpos, ypos)
            self.whex.asciicursor.draw(xpos, ypos)

            self.heditor.selection.select(xpos, ypos, xpos, ypos, True)
	if not self.heditor.preview:
            self.heditor.right.decode.update()
            self.heditor.infos.update()

    def mouseReleaseEvent(self, event):
        pass


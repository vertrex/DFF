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
from PyQt4.QtGui import *
from PyQt4.QtCore import *

class selection():
    def __init__(self, parent):
        self.init(parent)
        self.initFont()

    def init(self, parent):
        #Parent widgets and items
        self.heditor = parent
        self.hexitem = parent.whex.hexitem
        self.asciitem = parent.whex.asciitem

        #Start selection
        self.xstart = 0
        self.ystart = 0
        #End Selection
        self.xend = 0
        self.yend = 0

        self.length = 0
        self.offset = 0
        self.startoffset = 0
        self.endoffset = 0
        self.way = 0

    def initFont(self):
        self.font = QFont("Gothic")
        self.font.setFixedPitch(1)
        self.font.setBold(False)
        self.font.setPixelSize(14)

    def setWay(self):
        if ((self.xend - self.xstart) < 0) or ((self.yend - self.ystart) < 0):
            self.way = 0
        else:
            self.way = 1

    def setData(self):
        startoff = self.heditor.currentOffset + ((self.ystart * self.heditor.bytesPerLine) + self.xstart)
        endoff = self.heditor.currentOffset + ((self.yend * self.heditor.bytesPerLine) + self.xend)
        selen = endoff - startoff
        if selen < 0:
            selen = selen * -1
            self.offset = startoff - selen
            self.startoffset = self.offset
            self.xinit = self.xend
            self.yinit = self.yend
        else:
            self.offset = startoff + selen
            self.startoffset = startoff
            self.xinit = self.xstart
            self.yinit = self.ystart
        self.length = selen

    def setCount(self):
        self.ycount = self.length / self.heditor.bytesPerLine
        self.xcount = self.length % self.heditor.bytesPerLine
        if self.way > 0:
            self.xcount += 1

    def select(self, xstart, ystart, xend, yend, first = False):
        self.resetSelection()
        if first:
            self.xstart = xstart
            self.ystart = ystart
            self.xend = xend
            self.yend = yend
        else:
            self.xend = xend
            self.yend = yend
        #Set Data selection
        self.setWay()
        self.setData()
        self.setCount()

        self.heditor.whex.hexcursor.update()
        self.heditor.whex.asciicursor.update()
        
        #Colorize process
        if self.length > 0:
            self.colorize()

    def update(self):
        self.initStartPosition()
        if self.length > 0:
            self.colorize()

    def initStartPosition(self):
        if self.way > 0:
            startrange = (self.offset - self.length) - self.heditor.currentOffset
        else:
            startrange = self.offset - self.heditor.currentOffset

        if startrange < 0:
            selen = self.length - (startrange * -1)
            if selen < 0:
                selen = 0
            startrange = 0
        else:
            selen = self.length

        self.yinit = startrange / self.heditor.bytesPerLine
        self.xinit = startrange % self.heditor.bytesPerLine

        self.ycount = selen / self.heditor.bytesPerLine
        self.xcount = selen % self.heditor.bytesPerLine

    def colorize(self):
        #Get hex cursor
        hexcur = self.getCursorSelection(0)
        self.colorizeCursor(hexcur, 0)
        asciicur = self.getCursorSelection(1)
        self.colorizeCursor(asciicur, 1)

    def getCursorSelection(self, item):
        #Init Position
        if item == 0:
            #Hexadecimal
            cursor = self.hexitem.textCursor()
            xway = QTextCursor.NextWord
        else:
            #Ascii
            cursor = self.asciitem.textCursor()
            xway = QTextCursor.NextCharacter

        cp = 0
        while cp < self.yinit:
            cursor.movePosition(QTextCursor.Down, QTextCursor.MoveAnchor)
            cp += 1
        cp = 0
        while cp < self.xinit:
            cursor.movePosition(xway, QTextCursor.MoveAnchor)
            cp += 1

        #Move Cursor
        cp = 0
        while cp < self.ycount:
            cursor.movePosition(QTextCursor.Down, QTextCursor.KeepAnchor)
            cp += 1

        cp = 0            
        while cp < self.xcount:
            cursor.movePosition(xway, QTextCursor.KeepAnchor)
            cp += 1

        return cursor
    
    #Item: 0 hex 1 ascii
    def colorizeCursor(self, cursor, item):
        format = QTextCharFormat()
        format.setFont(self.font)
        if item == 0:
            format.setForeground(QBrush(QColor(Qt.blue)))
        else:
            format.setForeground(QBrush(QColor(Qt.blue)))
        cursor.setCharFormat(format)

    def resetSelection(self):
        self.resetColorSelection(self.hexitem.textCursor())
        self.resetColorSelection(self.asciitem.textCursor())

    def resetColorSelection(self, cursor):
        #Set Format
        bformat = QTextCharFormat()
        bformat.setFont(self.font)
        #Set Black Color
        cursor.movePosition(QTextCursor.Start)
        cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
        cursor.setCharFormat(bformat)
        cursor.movePosition(QTextCursor.Start)

    def hexCopy(self):
        if self.way > 0:
            off = self.offset - self.length
        else:
            off = self.offset

        buff = self.heditor.readHexValue(off, self.length)
#        print buff

    def createToolBar(self):
        self.toolbar = QToolBar()
	self.toolbar.setObjectName("hexedit selection toolbar")

        self.copy = QAction(QIcon(":bookmark_add.png"),  "Copy selection",  self.toolbar)
        self.toolbar.addAction(self.copy)

        
class pageSelection():
    def __init__(self, parent):
        self.init(parent)
        self.initBrush()

    def init(self, parent):
        self.heditor = parent
        self.pview = self.heditor.wpage.view

        self.items = self.pview.pageItems

        self.pageoffset = 0
        self.blockoffset = 0

        self.startid = 0
        self.endid = 0

        self.startcount = 0
        self.endcount = 0

        self.length = 0

        # 0: click | 1: selection
        self.mode = 0
        self.way = 0

    def initBrush(self):
        self.hcolor = QColor(Qt.green)
        self.hbrush = QBrush(self.hcolor, Qt.SolidPattern)
#        self.setBrush(self.brush)

    def initPen(self):
        self.pen = QPen(QColor(Qt.black))
        self.setPen(self.pen)


    def selectPage(self, offset):
        if self.length == 0:
            self.pageoffset = offset

    def select(self, id, startBlockOffset, mode):
        if mode == 0:
            self.startid = id
            self.startcount = id

            self.endid = id
            self.endcount = id
            self.length = 0
#            inblock = id / self.heditor.pagesPerBlock
#            startoffset = startBlockOffset + (inblock * (self.heditor.pageSize * self.heditor.pagesPerBlock))
#            self.blockoffset = startBlockOffset

            self.pageoffset = self.heditor.startBlockOffset + (id * self.heditor.pageSize)
            self.heditor.readOffset(self.pageoffset)
#            #Update Hexview scrollbar
            value = self.heditor.whex.offsetToValue(self.pageoffset)
            self.heditor.whex.scroll.setValue(value)
            self.colorizePages()
            self.mode = 1
        else:
            self.endid = id
            
            if self.endid < self.startid:
                self.startcount = self.endid
                self.endcount = self.startid
                self.length = self.startid - self.endid
                self.way = 0
            else:
                self.startcount = self.startid
                self.endcount = self.endid
                self.length = self.endid - self.startid
                self.way = 1

            self.pageoffset = self.heditor.startBlockOffset + (self.startcount * self.heditor.pageSize)
            self.colorizePages()

    def colorizePages(self):
        self.pview.resetSelection()
        if self.length == 0 and (self.startcount < len(self.items)):
#            print "len items : ", len(self.items), ": ", self.startcount
            self.items[self.startcount].setBrush(self.hbrush)
        else:
#            print "len items : ", len(self.items), ": ", self.startcount
            if (self.startcount  < len(self.items)) or (self.endcount < len(self.items)):
                for item in self.items[self.startcount:self.endcount + 1]:
                    item.setBrush(self.hbrush)

    def update(self):
        ret = self.initStartPosition()
        if ret == 0:
            self.pview.resetSelection()
            return 0
        else:
            self.colorizePages()
            return 1

    def initStartPosition(self):
        endzone = self.heditor.startBlockOffset + (self.pview.lines * (self.heditor.pageSize * self.heditor.pagesPerBlock))
        endoffset = self.pageoffset + (self.length * self.heditor.pageSize)

#        if (self.pageoffset >= self.heditor.startBlockOffset) and  (self.pageoffset < endzone):
        if (endoffset >= self.heditor.startBlockOffset) and (endoffset < endzone):
#            print "start page offset: ", self.heditor.startBlockOffset
            startblockid = (self.pageoffset - self.heditor.startBlockOffset) / self.heditor.pageSize
            endblockid = ((self.pageoffset - self.heditor.startBlockOffset) + (self.length * self.heditor.pageSize)) / self.heditor.pageSize
#            print "========"
#            print "sblockid: ", startblockid
#            print "eblockid: ", endblockid
#            print "mode: ", self.mode
#            print "way: ", self.way
            self.startcount = startblockid
            self.endcount = endblockid

            if self.startcount < 0:
                self.startcount = 0
        else:
            return 0

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
from PyQt4.QtCore import Qt, QLineF
from PyQt4.QtGui import QGraphicsView, QKeySequence, QHBoxLayout, QWidget, QFont, QGraphicsScene, QGraphicsLineItem, QGraphicsTextItem

from dff.modules.hexedit.hexItem import *
from dff.modules.hexedit.offsetItem import *
from dff.modules.hexedit.asciiItem import *
from dff.modules.hexedit.scrollbar import hexScrollBar

class wHex(QWidget):
    def __init__(self, parent):
        QWidget.__init__(self)
        self.init(parent)
        self.initShape()
        self.initMode()

    def init(self, parent):
        self.heditor = parent

    def initShape(self):
        self.hbox = QHBoxLayout()

        self.hbox.setContentsMargins(0, 0, 0, 0)
        self.view = hexView(self)
        self.scroll = hexScrollBar(self)

        #Init Items
        self.hexitem = hexItem(self)
        self.offsetitem = offsetItem(self)
        self.asciitem = asciiItem(self)

        self.hexcursor = hexCursor(self)
        self.asciicursor = asciiCursor(self)

        self.view.setItems()
        self.view.setCursors()

        self.hbox.addWidget(self.view)
        self.hbox.addWidget(self.scroll)

        self.setLayout(self.hbox)

    #Set Long File Mode
    def initMode(self):
        self.lfmod = False
        self.maxint = 2147483647
        self.lines = self.heditor.filesize / self.heditor.bytesPerLine
        if self.isInt(self.lines):
            self.scroll.max = self.lines - 1
        else:
            self.lfmod = True
            self.scroll.max = self.maxint - 1
        self.scroll.setValues()

    def offsetToValue(self, offset):
        if self.isLFMOD():
            return ((self.maxint * offset) / self.heditor.filesize)
        else:
            return (offset / self.heditor.bytesPerLine)

    def isLFMOD(self):
        return self.lfmod

    def isInt(self, val):
        try:
            res = int(val)
            if res <  2147483647:
                return True
            else:
                return False
        except ValueError, TypeError:
            return False
        else:
            return False

class hexView(QGraphicsView):
    def __init__(self, parent):
        QGraphicsView.__init__(self, None, parent)
        self.init(parent)
        self.initShape()

    def init(self, parent):
        self.whex = parent
        self.heditor = self.whex.heditor
        #Init scene
        self.__scene = QGraphicsScene(self)
        self.setScene(self.__scene)

        #Get heditor stuff
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setAlignment(Qt.AlignLeft)

    def setItems(self):
        self.__scene.addItem(self.whex.offsetitem)
        self.__scene.addItem(self.whex.hexitem)
        self.__scene.addItem(self.whex.asciitem)

    def initShape(self):
        self.initHeads()
        #Line decoration
        offsetLine = QGraphicsLineItem(QLineF(90, 0, 90, 700))
        asciiLine = QGraphicsLineItem(QLineF(480, 0, 480, 700))
        #Add to scene
        self.__scene.addItem(offsetLine)
        self.__scene.addItem(asciiLine)

    def setCursors(self):
        self.__scene.addItem(self.whex.hexcursor)
        self.__scene.addItem(self.whex.asciicursor)

    def initHeads(self):
        self.offHead = QGraphicsTextItem()
        self.hexHead = QGraphicsTextItem()
        self.asciiHead = QGraphicsTextItem()
        #Set Color
        self.offHead.setDefaultTextColor(QColor(Qt.red))
        self.hexHead.setDefaultTextColor(QColor(Qt.black))
        self.asciiHead.setDefaultTextColor(QColor(Qt.darkCyan))
        #Create Font
        self.font = QFont("Gothic")
        self.font.setFixedPitch(1)
        self.font.setBold(False)
        self.font.setPixelSize(14)
        #Set Font
        self.offHead.setFont(self.font)
        self.hexHead.setFont(self.font)
        self.asciiHead.setFont(self.font)
        #Set Text
        self.offHead.setPlainText("Offset")
        self.hexHead.setPlainText("0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F")
        self.asciiHead.setPlainText("Ascii")
        #Position
        self.offHead.setPos(20, 0)
        self.hexHead.setPos(95, 0)
        self.asciiHead.setPos(520, 0)
        #Add to scene
        self.__scene.addItem(self.offHead)
        self.__scene.addItem(self.hexHead)
        self.__scene.addItem(self.asciiHead)
        headLine = QGraphicsLineItem(QLineF(0, 20, 615, 20))
        self.__scene.addItem(headLine)


    def move(self, step, way):
        #step: line = 1 * bytesPerLine, page = pagesize, wheel = 3 * bytesPerLine
        offset = self.heditor.currentOffset
        if way == 0:
        #UP
            if (offset - (step * self.heditor.bytesPerLine)) >= 0:
                self.heditor.readOffset(offset - (step * self.heditor.bytesPerLine))
                if self.whex.isLFMOD():
                    self.whex.scroll.setValue(self.whex.offsetToValue(offset - step * (self.heditor.bytesPerLine)))
                else:
                    self.whex.scroll.setValue(self.whex.scroll.value() - step)
            else:
                self.heditor.readOffset(0)
                self.whex.scroll.setValue(0)
        elif way == 1:
        #Down
            if (offset + (step * self.heditor.bytesPerLine)) <= (self.heditor.filesize - (step * self.heditor.bytesPerLine)):
                self.heditor.readOffset(offset + (step * self.heditor.bytesPerLine))
                if self.whex.isLFMOD():
                    self.whex.scroll.setValue(self.whex.offsetToValue(offset + step * (self.heditor.bytesPerLine)))
                else:
                    self.whex.scroll.setValue(self.whex.scroll.value() + step)
            else:
                self.heditor.readOffset(self.heditor.filesize - 5 * (self.heditor.bytesPerLine))
                self.whex.scroll.setValue(self.whex.scroll.max)
            


####################################
#        Navigation Operations     #
####################################

    def wheelEvent(self, event):
        offset = self.heditor.currentOffset
        if event.delta() > 0:
            self.move(3, 0)
        else:
            self.move(3, 1)


    def keyPressEvent(self, keyEvent):
#        off = self.heditor.currentOffset
        if keyEvent.matches(QKeySequence.MoveToNextPage):
            self.move(self.heditor.pageSize / self.heditor.bytesPerLine, 1)
        elif keyEvent.matches(QKeySequence.MoveToPreviousPage):
            self.move(self.heditor.pageSize / self.heditor.bytesPerLine, 0)
        #elif keyEvent.matches(QKeySequence.MoveToNextWord):
            #print "Next Word"
        #elif keyEvent.matches(QKeySequence.MoveToPreviousWord):
            #print "Previous word"
        #elif keyEvent.matches(QKeySequence.MoveToNextLine):
            #print "Next Line"
        #elif keyEvent.matches(QKeySequence.MoveToPreviousLine):
            #print "Previous Line"


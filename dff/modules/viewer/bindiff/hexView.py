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

from dff.modules.bindiff.hexItem import *
from dff.modules.bindiff.asciiItem import *
from dff.modules.bindiff.offsetItem import *

class wHex(QWidget):
    def __init__(self, parent):
        QWidget.__init__(self)
        self.init(parent)
        self.initShape()

    def init(self, parent):
        self.bdiff = parent
        self.bytesPerLine = self.bdiff.bytesPerLine

    def initShape(self):
        self.hbox = QHBoxLayout()

        self.view = hexView(self)

        #Init Items
        self.hexitem = hexItem(self)
        self.offsetitem = offsetItem(self)
        self.asciitem = asciiItem(self)

        self.view.setItems()

        self.hbox.addWidget(self.view)
        self.setLayout(self.hbox)

    def updateItems(self, offset, buffer):
        self.offsetitem.printFullOffset(offset, (len(buffer) / self.bytesPerLine))
        self.hexitem.dumpHexBuffer(buffer)
        self.asciitem.printBuffer(buffer)

        
class hexView(QGraphicsView):
    def __init__(self, parent):
        QGraphicsView.__init__(self)
        self.init(parent)
        self.initShape()

    def init(self, parent):
        self.whex = parent
        self.bdiff = self.whex.bdiff
        #Init scene
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        #Get bdiff stuff
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setAlignment(Qt.AlignLeft)

    def setItems(self):
        self.scene.addItem(self.whex.offsetitem)
        self.scene.addItem(self.whex.hexitem)
        self.scene.addItem(self.whex.asciitem)

    def initShape(self):
        self.initHeads()
        #Line decoration
        offsetLine = QGraphicsLineItem(QLineF(90, 0, 90, 700))
        asciiLine = QGraphicsLineItem(QLineF(480, 0, 480, 700))
        #Add to scene
        self.scene.addItem(offsetLine)
        self.scene.addItem(asciiLine)

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
        self.scene.addItem(self.offHead)
        self.scene.addItem(self.hexHead)
        self.scene.addItem(self.asciiHead)
        headLine = QGraphicsLineItem(QLineF(0, 20, 615, 20))
        self.scene.addItem(headLine)

    def setSyncView(self, whexview):
        self.whexviewsync = whexview

    def move(self, step, way):
        #step: line = 1 * bytesPerLine, page = pagesize, wheel = 3 * bytesPerLine
        offset = self.bdiff.currentOffset
#        print offset
        if way == 0:
        #UP
            if (offset - (step * self.bdiff.bytesPerLine)) >= 0:
                self.bdiff.readOffset(offset - (step * self.bdiff.bytesPerLine))
                if self.bdiff.scrollbar.isLFMOD():
                    self.bdiff.scrollbar.setValue(self.bdiff.scrollbar.offsetToValue(offset - (step * self.bdiff.bytesPerLine)))
                else:
                    self.bdiff.scrollbar.setValue(self.bdiff.scrollbar.value() - step)
            else:
                self.bdiff.readOffset(0)
                self.bdiff.scrollbar.setValue(0)
        elif way == 1:
       #Down
            if (offset + (step * self.bdiff.bytesPerLine)) <= (self.bdiff.masterFileSize - (step * self.bdiff.bytesPerLine)):
                self.bdiff.readOffset(offset + (step * self.bdiff.bytesPerLine))
                if self.bdiff.scrollbar.isLFMOD():
                    self.bdiff.scrollbar.setValue(self.bdiff.scrollbar.offsetToValue(offset + (step * self.bdiff.bytesPerLine)))
                else:
                    self.bdiff.scrollbar.setValue(self.bdiff.scrollbar.value() + step)
            else:
                self.bdiff.readOffset(self.bdiff.masterFileSize - 5 * (self.bdiff.bytesPerLine))             
                self.bdiff.scrollbar.setValue(self.bdiff.scrollbar.max)


####################################
#        Navigation Operations     #
####################################

    def wheelEvent(self, event):
        offset = self.bdiff.currentOffset
        if event.delta() > 0:
            self.move(3, 0)
            self.whexviewsync.move(3, 0)
        else:
            self.move(3, 1)
            self.whexviewsync.move(3, 1)


    def keyPressEvent(self, keyEvent):
        off = self.bdiff.currentOffset
        if keyEvent.matches(QKeySequence.MoveToNextPage):
            self.move(self.bdiff.pageSize / self.bdiff.bytesPerLine, 1)
            self.whexviewsync.move(self.bdiff.pageSize / self.bdiff.bytesPerLine, 1)
        elif keyEvent.matches(QKeySequence.MoveToPreviousPage):
            self.move(self.bdiff.pageSize / self.bdiff.bytesPerLine, 0)
            self.whexviewsync.move(self.bdiff.pageSize / self.bdiff.bytesPerLine, 0)
        elif keyEvent.matches(QKeySequence.MoveToNextLine):
            self.move(1, 1)
            self.whexviewsync.move(1, 1)
        elif keyEvent.matches(QKeySequence.MoveToPreviousLine):
            self.move(1, 0)
            self.whexviewsync.move(1, 0)


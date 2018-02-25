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
from PyQt4.QtCore import QString, Qt, QPointF
from PyQt4.QtGui import QWidget, QFont, QColor, QBrush, QPen, QGraphicsRectItem

class hexCursor(QGraphicsRectItem):
    def __init__(self, whex):
        QGraphicsRectItem.__init__(self)
        self.init(whex)

    def init(self, whex):
        self.whex = whex
        self.hexitem = self.whex.hexitem
        self.bdiff = self.whex.bdiff

        self.w = self.hexitem.byteW
        self.h = self.w

        self.xpos = 0
        self.ypos = 0

        self.brush = QBrush(Qt.NoBrush)
        self.pen = QPen(QColor(Qt.darkCyan))

        self.setBrush(self.brush)
        self.setPen(self.pen)
#        self.setParentItem(parent)

    def draw(self, posx, posy):
        x = 95 + (posx * self.hexitem.byteW) + (posx * self.hexitem.charW) + (self.hexitem.startBlank / 2)
        y = 25 + (posy * self.hexitem.byteH) + (self.hexitem.startBlank / 2)

        self.xpos = posx
        self.ypos = posy

        self.setRect(x, y, self.w, self.h)
        self.setVisible(True)

    def update(self):
        x = (self.bdiff.selection.offset - self.bdiff.currentOffset) % self.bdiff.bytesPerLine
        y = (self.bdiff.selection.offset - self.bdiff.currentOffset) / self.bdiff.bytesPerLine
        if y >= 0 and y < (self.bdiff.readSize / self.bdiff.bytesPerLine):
            self.setVisible(True)
            self.xpos = x
            self.ypos = y
            self.draw(x, y)
        else:
            self.setVisible(False)
#        if (self.bdiff.selection.offset >= self.bdiff.currentOffset) and (self.bdiff.selection.offset < (self.bdiff.currentOffset + self.bdiff.pageSize)):
            

#For futur implementations
#    def moveUp(self, move):
#        if (self.ypos - move) > 0:
#            self.ypos -= move
#            x = 95 + (self.xpos * 20) + (self.xpos * 4)
#            y = 25 + (self.ypos * 15) + (self.ypos * 4)
#            self.setRect(x, y, self.w, self.h)
#        else:
#            self.setVisible(False)

#    def moveDown(self, move):
#        if (self.ypos + move) < 32:
#            self.ypos += move
#            x = 95 + (self.xpos * 20) + (self.xpos * 4)
#            y = 25 + (self.ypos * 15) + (self.ypos * 4)
#            self.setRect(x, y, self.w, self.h)
#        else:
#            self.setVisible(False)
    
class asciiCursor(QGraphicsRectItem):
    def __init__(self, whex):
        QGraphicsRectItem.__init__(self)
        self.init(whex)

    def init(self, whex):
        self.whex = whex
        self.asciitem = self.whex.asciitem
        self.bdiff = self.whex.bdiff

        self.w = self.asciitem.byteW
        self.h = self.w * 2

        self.brush = QBrush(Qt.NoBrush)
        self.pen = QPen(QColor(Qt.black))

        self.setBrush(self.brush)
        self.setPen(self.pen)
#        self.setParentItem(whex)

    def draw(self, posx, posy):
        x = 95 + 390 + (posx * self.asciitem.byteW) + (self.asciitem.startBlank / 2)
        y = 25 + (posy * self.asciitem.byteH) + (self.asciitem.startBlank / 2)
        
        self.xpos = posx
        self.ypos = posy

        self.setRect(x, y, self.w, self.h)
        self.setVisible(True)

    def update(self):
        x = (self.bdiff.selection.offset - self.bdiff.currentOffset) % self.bdiff.bytesPerLine
        y = (self.bdiff.selection.offset - self.bdiff.currentOffset) / self.bdiff.bytesPerLine
        if y >= 0 and y < (self.bdiff.readSize / self.bdiff.bytesPerLine):
            self.setVisible(True)
            self.ypos = y
            self.xpos = x
            self.draw(x, y)
        else:
            self.setVisible(False)

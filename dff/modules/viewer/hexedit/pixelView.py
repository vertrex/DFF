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
import sip
import time
import struct
import binascii

from PyQt4.QtCore import *
from PyQt4.QtGui import *

from dff.api.exceptions.libexceptions import *

from dff.modules.hexedit.scrollbar import byteScrollBar

class wPixel(QWidget):
    def __init__(self, parent):
        QWidget.__init__(self)
        self.init(parent)
        self.initShape()

    def init(self, parent):
        self.heditor = parent
        self.scroll = False

    def initShape(self):
        self.layout = QHBoxLayout()
        self.view = pixelView(self)
        self.layout.addWidget(self.view)

        if self.view.hmax > self.view.hcur:
            self.setScroll()
            self.layout.addWidget(self.scroll)
        else:
            self.scroll = False

        self.setLayout(self.layout)

    def setScroll(self):
        self.scroll = byteScrollBar(self)
        self.scroll.refreshValues()


class pixelView(QGraphicsView):
    def __init__(self, wpixel):
        QGraphicsView.__init__(self)
        self.init(wpixel)
        self.initShape()
#        self.setColors()
#        self.read_image(self.currentOffset)

    def init(self, wpixel):
        self.wpixel = wpixel
        self.heditor = wpixel.heditor

        self.scale = 1

        self.file = self.heditor.file
        self.filesize = self.heditor.filesize

        self.w = 512
        self.h = 512

        self.hmax = self.filesize / self.w
        if self.filesize % self.w > 0:
            self.hmax += 1
        
        self.hcur = self.height()

        self.currentOffset = 0
        self.mformat = QImage.Format_Mono
        self.iformat = QImage.Format_Indexed8
        self.rformat = QImage.Format_RGB32
        self.arformat = QImage.Format_ARGB32_Premultiplied
        #0 = Red
        #1 = Green
        #2 = Blue
        #3 = Ascii
        #4 = 256
        self.icolor = 1
        #Indexed = 0
        #Mono = 1
        #RGB = 2
        #ARGB = 3
        self.format = 2

        self.wheelpad = 10
        self.pagepad = self.hcur - self.wheelpad
        
    def initShape(self):
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
       
        self.setAlignment(Qt.AlignLeft)
#        self.setAlignment(Qt.AlignTop)

        self.scene = QGraphicsScene()
        self.pixmap = QPixmap()
       
        self.pixmapitem = pixItem(self)
        self.pixmapitem.setPixmap(self.pixmap)

        self.scene.addItem(self.pixmapitem)
        self.setScene(self.scene)

    def setGreenColors(self, image):
        c = 0
        while c <= 255:
            v = qRgb(0, c, 0)
            image.setColor(c, v)
            c += 1

    def setRedColors(self, image):
        c = 0
        while c <= 255:
            v = qRgb(c, 0, 0)
            image.setColor(c, v)
            c += 1

    def setBlueColors(self, image):
        c = 0
        while c <= 255:
            v = qRgb(0, 0, c)
            image.setColor(c, v)
            c += 1

    def setAsciiColors(self, image):
    #ASCII printable: Dark Grey
    #CRLF: Yellow
    #Tab or space: Red
    #Other ascii grey clair
    #Other: White
        c = 0
        while c <= 255:
            if c > 32 and c < 127:
                v = qRgb(128, 128, 128)
                image.setColor(c, v)
            elif c == 10 or c == 13:
                v = qRgb(255, 255, 0)
                image.setColor(c, v)
            elif c == 32 or c == 9:
                v = qRgb(255, 0, 0)
                image.setColor(c, v)
            else:
                v = qRgb(255, 255, 255)
                image.setColor(c, v)
            c += 1

    def scalePixmap(self, value):
        matrix = QMatrix()
        matrix.scale(value, value)
#        pixorigin = self.pixmapitem.pixmap()
        pixorigin = self.pixmapitem.pixmap()
        zpix = pixorigin.transformed(matrix)
        self.pixmapitem.setPixmap(zpix)
#        self.heditor.wpixel.view.pixmapitem.scale(0, 0)
#        self.heditor.wpixel.view.pixmapitem.scale(value, value)


    def read_image(self, offset):
        self.currentOffset = offset
        self.file.seek(offset)
        toread = self.filesize - self.currentOffset
#        print "toread: ", toread, "calcul: ", (self.w * self.hcur), "calcul RGB: ", (self.w * self.hcur * 4)
        #If not 4Byte (RGB)
        if self.format < 2:
            if toread >= self.w * self.hcur:
                toread = self.w * self.hcur
                hei = self.hcur
            else:
                hei = toread / self.w
        else:
            if toread >= self.w * self.hcur * 4:
                toread = self.w * self.hcur * 4
                hei = self.hcur
            else:
                hei = (toread / 4) / self.w

        try:
            self.buff = self.file.read(self.w * hei * 4)
	    if len(self.buff) < (self.w * hei * 4):
	      leak = (self.w *hei * 4) - len(self.buff) 	
	      self.buff += leak* '\x00'
        #Create image with current format
            if self.format == 0:
                image = QImage(self.buff, self.w, hei, self.w, self.iformat)
                if self.icolor == 0:
                    self.setRedColors(image)
                elif self.icolor == 1:
                    self.setGreenColors(image)
                elif self.icolor == 2:
                    self.setBlueColors(image)
                elif self.icolor == 3:
                    self.setAsciiColors(image)
            elif self.format == 1:
                image = QImage(self.buff, self.w, hei, self.w, self.mformat)
            elif self.format == 2:
                image = QImage(self.buff, self.w, hei, self.w * 4, self.rformat)
            elif self.format == 3:
                image = QImage(self.buff, self.w, hei, self.w * 4, self.arformat)
	    self.pixmapitem.setPixmap(QPixmap().fromImage(image))
            if self.scale > 1:
                self.scalePixmap(self.scale)
        except vfsError, e:
            pass 

    def move(self, pad, dir):
        #dir: 0 DOWN | 1 UP
        offset = self.currentOffset
        if self.wpixel.scroll:
            if dir > 0:
                #UP
                if self.format < 2:
                    subOffset = pad * self.w
                else:
                    subOffset = pad * (self.w * 4)
                if offset - subOffset > 0:
                    offset = offset - subOffset
                else:
                    offset = 0
            else:
                #DOWN
                if self.format < 2:
                    addOffset = pad * self.w
                else:
                    addOffset = pad * (self.w * 4)

                if offset + addOffset < self.filesize:
                    offset = offset + addOffset
                else:
                    offset = self.filesize - (pad * self.w)
            self.read_image(offset)
            if self.format < 2:
                self.wpixel.scroll.setValue(offset / self.w)
            else:
                self.wpixel.scroll.setValue(offset / (self.w * 4))
            
    def resizeEvent(self, sEvent):
        self.hcur = sEvent.size().height()
        self.read_image(self.currentOffset)
        self.heditor.wpage.view.resizeEvent(sEvent)

    def wheelEvent(self, event):
        if event.delta() > 0:
            self.move(self.wheelpad, 1)
        else:
            self.move(self.wheelpad, 0)

    def keyPressEvent(self, keyEvent):
        if keyEvent.matches(QKeySequence.MoveToNextPage):
            self.move(self.pagepad, 0)
        elif keyEvent.matches(QKeySequence.MoveToPreviousPage):
            self.move(self.pagepad, 1)
        elif keyEvent.matches(QKeySequence.MoveToNextLine):
            self.move(self.wheelpad, 0)
        elif keyEvent.matches(QKeySequence.MoveToPreviousLine):
            self.move(self.wheelpad, 1)
        else:
            pass


class pixItem(QGraphicsPixmapItem):
    def __init__(self, parent):
        QGraphicsPixmapItem.__init__(self)    
        self.view = parent
        self.heditor = parent.heditor
        self.rect = False
        self.offsetitem = False
        self.setAcceptHoverEvents(True)

    def getOffset(self, x, y):
        if self.view.format < 2:
            offset = self.view.currentOffset + (self.view.w  * (int(y) / self.view.scale)) + (int(x) / self.view.scale)
        else:
            offset = self.view.currentOffset + ((self.view.w * 4) * (int(y) / self.view.scale)) + ((int(x) * 4) / self.view.scale)
        return int(offset)

    def hoverMoveEvent(self, hEvent):
        x = hEvent.pos().x()
        y = hEvent.pos().y()
        
        offset = self.getOffset(x, y)
        coffset = QString("Off: ")
        if self.heditor.decimalview:
            coffset.append("%2.d" % offset)
        else:
            coffset.append("%2.x" % offset)
        cw = 8
        #Display Rect background
        if not self.rect:
            self.rect = QGraphicsRectItem(x + cw, y, (cw * coffset.length()), cw + 10)
            self.rect.setPen(QPen(Qt.black))
            self.rect.setBrush(QBrush(Qt.white))
            self.rect.setZValue(1)
            self.view.scene.addItem(self.rect)
        else:
            self.rect.setRect(x + cw, y, (cw * coffset.length()), cw + 10)
        #Display Offset
        if not self.offsetitem:
            self.offsetitem = QGraphicsSimpleTextItem()
            self.offsetitem.setText(coffset)
            self.offsetitem.setPos(x + cw + 5, y)
            self.offsetitem.setZValue(2)
            self.view.scene.addItem(self.offsetitem)
        else:
            self.offsetitem.setText(coffset)
            self.offsetitem.setPos(x + cw + 5, y)

    def mousePressEvent(self, mEvent):
        x =  mEvent.pos().x()
        y =  mEvent.pos().y()
        offset = self.getOffset(x, y)
#        print "offset: ", offset
        self.heditor.readOffset(offset)
        value = self.heditor.whex.offsetToValue(offset)
        self.heditor.whex.scroll.setValue(value)

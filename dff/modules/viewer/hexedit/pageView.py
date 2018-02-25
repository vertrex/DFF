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

from PyQt4.QtCore import QString, Qt, SIGNAL, QLineF
from PyQt4.QtGui import QWidget, QFont, QBrush, QPen, QColor, QGraphicsView, QGraphicsScene, QResizeEvent, QGraphicsRectItem, QHBoxLayout, QGraphicsTextItem, QGraphicsLineItem, QGraphicsSimpleTextItem, QKeySequence

from dff.modules.hexedit.scrollbar import pageScrollBar
from dff.modules.hexedit.selection import pageSelection

class wPage(QWidget):
    def __init__(self, parent):
        QWidget.__init__(self)
        self.init(parent)
        self.initShape()

    def init(self, parent):
        self.heditor = parent
        self.scroll = False

    def initShape(self):
        self.layout = QHBoxLayout()
        self.view = pageView(self)
        self.layout.addWidget(self.view)
        self.setLayout(self.layout)

    def setScrollBar(self):
        self.scroll = pageScrollBar(self)
        self.layout.addWidget(self.scroll)


class pageView(QGraphicsView):
    def __init__(self, wpage):
        QGraphicsView.__init__(self)
        self.init(wpage)
        self.initShape()

#        self.selection = pageSelection(self.heditor)

    def init(self, wpage):
        self.wpage = wpage
        self.heditor = wpage.heditor
        self.filesize = self.heditor.filesize
        self.start = True

        self.pagew = 20
        self.pageh = 20

        self.pageItems = []
        self.offsetItems = []
        self.displayLines = 0

    def initShape(self):
        #Scene
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        #Font
        self.initFont()
        #Headers
        self.setHeads(self.heditor.pagesPerBlock)

        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setAlignment(Qt.AlignLeft)

    def initFont(self):
        self.font = QFont("Gothic")
        self.font.setFixedPitch(1)
        self.font.setBold(False)
        self.font.setPixelSize(14)

    def setHeads(self, pagesPerBlock):
        if self.heditor.pageOffView:
            self.setOffsetHead()
        else:
            self.setBlockHead()
        self.setPageHead(self.heditor.pagesPerBlock)

        linesize = 95 + (self.heditor.pagesPerBlock * (self.pagew + 2))
        #Decoration
        headLine = QGraphicsLineItem(QLineF(0, 20, linesize, 20))
        self.scene.addItem(headLine)
        headOffLine = QGraphicsLineItem(QLineF(90, 0, 90, 700))
        self.scene.addItem(headOffLine)


    def setOffsetHead(self):
        self.offHead = QGraphicsTextItem()
        self.offHead.setDefaultTextColor(QColor(Qt.red))
        self.offHead.setFont(self.font)
        self.offHead.setPlainText("Offset(Kb)")
        self.offHead.setPos(5, 0)
        self.scene.addItem(self.offHead)

    def setPageHead(self, len):
        count = 0
        x = 95
        while count < len:
            item = QGraphicsSimpleTextItem()
            item.setFont(self.font)
            item.setText("%.2x" % count)
            item.setPos(x, 3)
            self.scene.addItem(item)
            x += self.pagew + 2
            count += 1

    def setBlockHead(self):
        self.blockHead = QGraphicsTextItem()
        self.blockHead.setDefaultTextColor(QColor(Qt.red))
        self.blockHead.setFont(self.font)
        self.blockHead.setPlainText("Block")
        self.blockHead.setPos(15, 0)
        self.scene.addItem(self.blockHead)

    def initOffsetItems(self):
        count = 0
        x = 0
        y = 25
        while count <= self.displayLines:
            item = QGraphicsTextItem()
            item.setDefaultTextColor(QColor(Qt.red))
            item.setFont(self.font)
            item.setPos(x, y)
            self.offsetItems.append(item)
            y += self.pageh + 2
            count += 1
        #Add Items in scene
        for item in self.offsetItems:
            self.scene.addItem(item)

    def initPageItems(self):
        id = 0
        countpage = 0
        startx = 95
        starty = 25
        x = startx
        y = starty
        line = 0
        while line <= self.displayLines:
            while countpage < self.heditor.pagesPerBlock:
                p = page(x, y, id, self)
                self.pageItems.append(p)
                id += 1
#                self.scene.addItem(sec)
                x += self.pagew + 2
                countpage += 1
            x = startx
            y += self.pageh + 2
            countpage = 0
            line += 1
        #Add items in scene
        for item in self.pageItems:
            self.scene.addItem(item)

    def hidePageItems(self, startid):
        end = len(self.pageItems)
        for item in self.pageItems[startid:end]:
            item.setVisible(False)

    def setAllPageItemsVisible(self):
        for item in self.pageItems:
            item.setVisible(True)

    def hideOffsetItems(self, startid):
        end = len(self.offsetItems)
        for item in self.offsetItems[startid:end]:
            item.setVisible(False)

    def setAllOffsetItemsVisible(self):
        for item in self.offsetItems:
            item.setVisible(True)

    def appendOffsetItems(self, linesToAppend):
        count = 0
        x = 0
        y = 25 + (len(self.offsetItems) * (self.pageh + 2))
#        print "Y append offset ", y
        while count <= linesToAppend:
            item = QGraphicsTextItem()
            item.setDefaultTextColor(QColor(Qt.red))
            item.setFont(self.font)
            item.setPos(x, y)
            self.offsetItems.append(item)
            self.scene.addItem(item)
            y += self.pageh + 2
            count += 1

    def appendPageItems(self, linesToAppend):
        count = 0
        cp = 0
        x = 95
        y = 25 + ((len(self.pageItems) / self.heditor.pagesPerBlock) * (self.pageh + 2))
        id = len(self.pageItems)

        while count <= linesToAppend:
            while cp < self.heditor.pagesPerBlock:
                item = page(x, y, id, self)
                self.pageItems.append(item)
                self.scene.addItem(item)
                id += 1
                x += self.pagew + 2
                cp += 1
            count += 1
            x = 95
            y += self.pageh + 2

    def refreshOffsetItems(self, offset):
        #Check if end of pages or if number of pages < display pages
        self.setAllOffsetItemsVisible()

        block = (offset / self.heditor.pageSize) / self.heditor.pagesPerBlock
        startBlockOffset = block * (self.heditor.pagesPerBlock * self.heditor.pageSize)


        lineToDisplay = ((self.filesize - offset) / self.heditor.pageSize) / self.heditor.pagesPerBlock


        if ((self.filesize - offset) / self.heditor.pageSize) % self.heditor.pagesPerBlock > 0:
            lineToDisplay += 1

        if lineToDisplay >= self.displayLines:
            offset = startBlockOffset
            for item in self.offsetItems[0:self.displayLines]:
                if self.heditor.decimalview:
                    if self.heditor.pageOffView:
                        offlabel = QString("%.10d" % (offset / 1024))
                    else:
                        offlabel = QString("%.10d" % (offset / (self.heditor.pageSize * self.heditor.pagesPerBlock)))
                else:
                    if self.heditor.pageOffView:
                        offlabel = QString("%.10x" % (offset / 1024))
                    else:
                        offlabel = QString("%.10x" % (offset / (self.heditor.pageSize * self.heditor.pagesPerBlock)))
                item.setPlainText(offlabel)
                offset = offset + (self.heditor.pagesPerBlock * self.heditor.pageSize)
            self.heditor.startBlockOffset = startBlockOffset
        else:
            if lineToDisplay == 0:
                lineToDisplay = 5
                offset = startBlockOffset - (lineToDisplay * self.heditor.pagesPerBlock * self.heditor.pageSize)
                if ((self.filesize - offset) / self.heditor.pageSize) % self.heditor.pagesPerBlock > 0:
                    lineToDisplay += 1

                self.heditor.startBlockOffset = offset

            for item in self.offsetItems[0:lineToDisplay]:
                if self.heditor.decimalview:
                    if self.heditor.pageOffView:
                        offlabel = QString("%.10d" % (offset / 1024))
                    else:
                        offlabel = QString("%.10d" % (offset / (self.heditor.pageSize * self.heditor.pagesPerBlock)))
                else:
                    if self.heditor.pageOffView:
                        offlabel = QString("%.10x" % (offset / 1024))
                    else:
                        offlabel = QString("%.10x" % (offset / (self.heditor.pageSize * self.heditor.pagesPerBlock)))
                item.setPlainText(offlabel)
                offset = offset + (self.heditor.pagesPerBlock * self.heditor.pageSize)
            self.hideOffsetItems(lineToDisplay)

    def refreshPageItems(self, offset):
        self.setAllPageItemsVisible()
        maxpages = self.displayLines * self.heditor.pagesPerBlock
        displaypages = (self.filesize - offset) / self.heditor.pageSize

        if displaypages <= maxpages:
            if displaypages == 0:
                startline = self.lines - 5
                startOffset = startline * (self.heditor.pageSize * self.heditor.pagesPerBlock)
                rangeOffset = self.filesize - startOffset
                newdisplaypages = rangeOffset / self.heditor.pageSize
                if rangeOffset % self.heditor.pageSize > 0:
                    newdisplaypages += 1

                self.hidePageItems(newdisplaypages)
                self.heditor.startBlockOffset = startOffset
            else:
                rangeOffset = self.filesize - offset
                rangePages = rangeOffset / self.heditor.pageSize
                rangeLines = rangePages / self.heditor.pagesPerBlock
                newdisplaypages = rangeOffset / self.heditor.pageSize

                if rangeOffset % self.heditor.pageSize > 0:
                    newdisplaypages += 1
 
                self.hidePageItems(newdisplaypages)
                self.heditor.startBlockOffset = offset
        else:
            self.heditor.startBlockOffset = offset

        self.heditor.pageselection.update()

    def refreshAllContent(self):
        self.scene.clear()
        del self.offsetItems[:]
        del self.pageItems[:]

        self.setHeads(self.heditor.pagesPerBlock)
        self.initOffsetItems()
        self.initPageItems()
        self.refreshOffsetItems(self.heditor.startBlockOffset)
        self.refreshPageItems(self.heditor.startBlockOffset)

    def lineToOffset(self, line):
        offset = (line * (self.heditor.pagesPerBlock * self.heditor.pageSize))
        return offset
 
    def lineToOffsetKb(self, line):
        offset = (line * (self.heditor.pagesPerBlock * self.heditor.pageSize)) / 1024
        return offset

    def lineToOffsetMb(self, line):
        offset = ((line * (self.heditor.pagesPerBlock * self.heditor.pageSize)) / 1024) / 1024
        return offset

    def lineToOffsetGb(self, line):
        offset = (((line * (self.heditor.pagesPerBlock * self.heditor.pageSize)) / 1024) / 1024) / 1024
        return offset

############################
#       Colorize Pages     #
############################

    def refreshPagesColor(self, id):
#        print "Refresh: ", id
        self.cleanSelection()
        self.pageItems[id].setBrush(QBrush(Qt.green, Qt.SolidPattern))

    def cleanSelection(self):
        item = self.pageItems[self.selectedPage]
        item.setBrush(item.brush)


############################
#       Resize Event       #
############################

    def resizeEvent(self, sizEvent):
        y = sizEvent.size().height()
        disline = (y / self.pageh)
        #Start
        if self.start == True:
            if self.height() < self.heditor.mainWindow.height():
                if disline > self.displayLines:
                    self.displayLines = (y / self.pageh)
                    #Lines
                    self.lines = self.filesize / (self.heditor.pagesPerBlock * self.heditor.pageSize)
                    #Init
                    self.initOffsetItems()
                    self.initPageItems()
                    #Refresh
                    self.refreshOffsetItems(0)
                    self.refreshPageItems(0)

                    if self.lines > self.displayLines:
                        self.wpage.setScrollBar()
                    else:
                        self.wpage.scroll = False
                    self.start = False
        else:
            range = disline - self.displayLines
            if range > 0:
                self.displayLines = (y / self.pageh)
                #Append
                self.appendOffsetItems(range)
                self.appendPageItems(range)
                #Refresh
            self.refreshOffsetItems(self.heditor.startBlockOffset)
            self.refreshPageItems(self.heditor.startBlockOffset)
#            self.heditor.footer.pixel.view.resizeEvent(sizEvent)


############################
#       CallBacks          #
############################

    def wheelEvent(self, event):
        offset = self.heditor.startBlockOffset
#        up = False
        if self.wpage.scroll:
            if event.delta() > 0:
            #UP
                subOffset = 3 * self.heditor.pagesPerBlock * self.heditor.pageSize
                if offset - subOffset > 0:
                    offset = offset - subOffset
                else:
                    offset = 0
            else:
            #DOWN
                addOffset = 3 * self.heditor.pagesPerBlock * self.heditor.pageSize
                if offset + addOffset < self.filesize:
                    offset = offset + addOffset
                else:
                    offset = self.filesize - (5 * self.heditor.pagesPerBlock * self.heditor.pageSize)
        #Set ScrollBar value:
            if offset < self.filesize - (5 * self.heditor.pagesPerBlock * self.heditor.pageSize):
                value = self.wpage.scroll.offsetToValue(offset)
                self.wpage.scroll.setValue(value)
                
                self.refreshOffsetItems(offset)
                self.refreshPageItems(offset)


    def keyPressEvent(self, keyEvent):
	pass
        #if keyEvent.matches(QKeySequence.MoveToNextPage):
            #print "Next block"
        #elif keyEvent.matches(QKeySequence.MoveToPreviousPage):
            #print "Previous block"
        #elif keyEvent.matches(QKeySequence.MoveToNextLine):
            #print "Next Line"
        #elif keyEvent.matches(QKeySequence.MoveToPreviousLine):
            #print "Previous Line"
        #else:
            #pass

    def resetSelection(self):
        for item in self.pageItems:
            item.setBrush(item.brush)

    def getPageID(self, x, y):
        startx = 95
        starty = 25

        #Set scrollbar seek
        hscroll = self.horizontalScrollBar()
        if hscroll.value() > 0:
            startx -= hscroll.value()

        xrange = x - startx
        if xrange > 0:
            xcut = (xrange / (self.pagew + 2))
#            print xcut
        else:
            xcut = 0

        yrange = y - starty
        if yrange > 0:
            ycut = yrange / (self.pageh + 2)
        else:
            ycut = 0
        id = (ycut * self.heditor.pagesPerBlock) + xcut
        return id

    def mousePressEvent(self, event):
        button = event.button()
        pos = event.pos()
        if event.button() == 1:
            #Get CLicked coordonates
            x = pos.x()
            y = pos.y()
            id = self.getPageID(x, y)
            self.resetSelection()
            self.heditor.pageselection.select(id, self.heditor.startBlockOffset, 0)

    def mouseMoveEvent(self, event):
        pos = event.pos()
        x = pos.x()
        y = pos.y()
        if self.heditor.pageselection.mode == 1:
            id = self.getPageID(x, y)
            self.resetSelection()
            self.heditor.pageselection.select(id, self.heditor.startBlockOffset, 1)
#        else:
#            id = self.getPageID(x, y)
#            self.pageItems[id].setBrush(self)
        
    def mouseReleaseEvent(self, event):
        self.heditor.pageselection.mode = 0

#        self.heditor.pageselection

class page(QGraphicsRectItem):
    def __init__(self, x, y, id, view):
        QGraphicsRectItem.__init__(self)
        self.initValues(x, y, id, view)
        self.initShape()

    def initValues(self, x, y, id, view):
        self.view = view
        self.heditor = self.view.heditor
        self.w = 20
        self.h = 20
        self.x = x
        self.y = y
        self.id = id

    def initShape(self):
        self.initBrush()
        self.initPen()
        self.setAcceptHoverEvents(True)
        self.setRect(self.x, self.y, self.w, self.h)

    def initBrush(self):
        self.color = QColor(Qt.darkGreen)
        self.brush = QBrush(self.color, Qt.SolidPattern)
        self.setBrush(self.brush)

    def initPen(self):
        self.pen = QPen(QColor(Qt.black))
        self.setPen(self.pen)

    def hoverEnterEvent(self, hoverEvent):
#        if self.view.selectedPage != self.id:
        self.setBrush(self.hbrush)

    def hoverLeaveEvent(self, hoverEvent):
#        if self.view.selectedPage != self.id:
        self.setBrush(self.brush)

#    def mousePressEvent(self, mousEvent):
#        button = mousEvent.button()
#        if button == 1:
#            offset = self.heditor.startBlockOffset + (self.id * self.heditor.pageSize)
#            self.heditor.readOffset(offset)
#            #Update Hexview scrollbar
#            value = self.heditor.whex.offsetToValue(offset)
#            self.heditor.whex.scroll.setValue(value)
#        else:
#            print "right click"

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
#  Christophe Malinge <cma@digital-forensic.org>
#
from datetime import timedelta

from PyQt4.QtCore import Qt, QRectF
from PyQt4.QtGui import QGraphicsView, QGraphicsScene, QPen

class PaintArea(QGraphicsView):
    def __init__(self, parent):
        QGraphicsView.__init__(self)
        self.init(parent)
        self.initShape()
        self.initCall = 2
        self.minimumWidth = 550
        self.setEnabled(False)

    def init(self, parent):
        self.timeline = parent
        self.pixmap = None
        self.image = None

    def initShape(self):
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setAlignment(Qt.AlignLeft)
        self.clicStart = None
        self.selectionRect = None

    def resizeEvent(self, sizEvent):
        if self.selectionRect and self.scene:
          self.scene.removeItem(self.selectionRect)
          self.selectionRect = None
          self.clicStart = None

        self.width = sizEvent.size().width()
        self.height = sizEvent.size().height()

        if self.initCall > 0:
          self.timeline.options.setMaximumWidth(self.timeline.options.minimumSizeHint().width())
          self.initCall -= 1

        if self.width < self.minimumWidth:
          self.timeline.setStateInfo('Unable to draw - Not enought width')
        else:
          self.timeline.workerThread.render()
          

    def mousePressEvent(self, mouseEvent):
      self.clicStart = mouseEvent.pos()
      if self.clicStart.x() < self.timeline.draw.yLeftMargin - 1:
        self.clicStart.setX(self.timeline.draw.yLeftMargin - 1)
      if self.clicStart.x() > self.timeline.ploter.width - self.timeline.m + 1:
        self.clicStart.setX(self.timeline.ploter.width - self.timeline.m + 1)
        
      if self.selectionRect:
        for item in self.scene.items():
          if str(type(item)) == "<class 'PyQt4.QtGui.QGraphicsRectItem'>":
            self.scene.removeItem(item)
        self.selectionRect = None
        self.timeline.options.zoomButton.setEnabled(False)
        self.timeline.options.exportButton.setEnabled(False)
        self.timeline.options.selectedNodes.setText('Nothing selected')
        if self.timeline.selDateMin:
          self.timeline.options.selStartTime.setText('From ' + str(self.timeline.fromUSec(self.timeline.baseDateMin).strftime('%d.%m.%Y %H:%M:%S')))
          self.timeline.options.selEndTime.setText('To ' + str(self.timeline.fromUSec(self.timeline.baseDateMax).strftime('%d.%m.%Y %H:%M:%S')))
        else:
          self.timeline.options.selStartTime.setText('No selection start time')
          self.timeline.options.selEndTime.setText('No selection end time')
        self.timeline.options.selectedNodes.setText('Nothing selected')
 

    def mouseMoveEvent(self, dragMoveEvent):
      if self.clicStart:
        if self.clicStart.x() < dragMoveEvent.x():
          x = self.clicStart.x()
          w = dragMoveEvent.x() - self.clicStart.x()
        else:
          x = dragMoveEvent.x()
          w = self.clicStart.x() - dragMoveEvent.x()

# Limit rectangle to selectable area
        if x < self.timeline.draw.yLeftMargin - 1:
          x = self.timeline.draw.yLeftMargin - 1
          w = self.clicStart.x() - x
        if x > self.timeline.ploter.width - self.timeline.m + 1:
          x = self.timeline.ploter.width - self.timeline.m + 1
          w = 0
        if x + w > self.timeline.ploter.width - self.timeline.m + 1:
          w = ((self.timeline.ploter.width - self.timeline.m + 1) - x)
        
        y = (self.timeline.m / 3) - 1
        h = self.height - self.timeline.m - self.timeline.m / 3 + 2
        if self.selectionRect and self.scene:
          self.scene.removeItem(self.selectionRect)
        self.selectionRect = self.scene.addRect(QRectF(x, y, w, h), QPen(Qt.DashDotDotLine))

    def mouseReleaseEvent(self, mouseEvent):
      if self.selectionRect:
        if self.clicStart.x() > mouseEvent.x():
          x1 = mouseEvent.x()
          x2 = self.clicStart.x()
        else:
          x1 = self.clicStart.x()
          x2 = mouseEvent.x()
        self.timeline.nodesInRange(x1, x2)
        start = self.timeline.draw.findXTime(x1)
        if start:
          self.timeline.options.selStartTime.setText('From ' + str(start.strftime('%d.%m.%Y %H:%M:%S')))
        end = self.timeline.draw.findXTime(x2)
        if end:
          self.timeline.options.selEndTime.setText('To ' + str(end.strftime('%d.%m.%Y %H:%M:%S')))

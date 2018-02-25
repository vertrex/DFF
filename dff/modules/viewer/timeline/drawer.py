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
from datetime import datetime

from PyQt4.QtCore import Qt, QPoint, QLineF

class Drawer():
  def __init__(self, timeline):
      self.timeline = timeline
      self.ploter = timeline.ploter
      self.options = timeline.options
      self.painter = None
      self.node = None
      self.m = timeline.m
      self.paddingYText = 4
      self.yLeftMargin = 0

  def setDynamicValues(self, timeline):
      self.painter = timeline.painter
      self.node = timeline.node
      self.baseDateMax = timeline.baseDateMax
      self.baseDateMin = timeline.baseDateMin
      self.selDateMin = timeline.selDateMin
      self.selDateMax = timeline.selDateMax
      self.maxOcc = timeline.maxOcc
      
  def drawGrid(self):
      """ Draw horizontal and vertical lines of grid

      yLeftMargin must be set, so call drawYInfos first.
      """
      pen = self.painter.pen()
      pen.setColor(Qt.black)
      pen.setStyle(Qt.SolidLine)
      self.painter.setPen(pen)
      # Draw X line
#      self.painter.drawLine(self.m,
      self.painter.drawLine(self.yLeftMargin,
                            self.ploter.height - self.m,
                            self.ploter.width - self.m,
                            self.ploter.height - self.m)
      # Draw Y line
#      self.painter.drawLine(self.m,
      self.painter.drawLine(self.yLeftMargin,
                            self.ploter.height - self.m,
#                            self.m,
                            self.yLeftMargin,
                            self.m / 3)

  def drawInfos(self):
    self.drawYInfos()
    self.drawXInfos()

  def drawXInfos(self):
    pen = self.painter.pen()
    i = 1
    scale = 6
    x = self.yLeftMargin
    y = self.ploter.height - self.m
    if not self.selDateMin:
      date = self.baseDateMin
      shift_date = (self.baseDateMax - self.baseDateMin) / scale
    else:
      date = self.selDateMin
      shift_date = (self.selDateMax - self.selDateMin) / scale
    while i <= scale + 1:
      pen.setColor(Qt.black)
      pen.setStyle(Qt.SolidLine)
      pos = QPoint(x - 40, y + 17)
      self.painter.setPen(pen)
# Draw vertical doted line
      self.painter.drawLine(x, y - 3, x, y + 3)
# Draw date
      self.painter.drawText(pos, str(self.timeline.fromUSec(date).strftime('%d.%m.%Y')))
# If number of days shown < scale, draw time
      if shift_date <= (86400 * 1000000):
        pos.setY(pos.y() + 15)
        pos.setX(pos.x() + 9)
# Draw time
        self.painter.drawText(pos, str(self.timeline.fromUSec(date).strftime('%H:%M:%S')))
      
      pen.setColor(Qt.gray)
      pen.setStyle(Qt.DotLine)
      self.painter.setPen(pen)
      if i != 1:
        self.painter.drawLine(x, y + 3, x, self.m / 3)
      x = self.yLeftMargin + (i * ((self.ploter.width - self.m - self.yLeftMargin) / (scale)))
      i += 1
      date += shift_date
    pen.setStyle(Qt.SolidLine)
    self.painter.setPen(pen)
    
  def drawYInfos(self):
    i = 1
    scale = 10.0
    y = self.m / 3

# Setting max occurence depending of zoom
    if not self.timeline.maxOccZoom:
      maxOcc = self.timeline.maxOcc
    else:
      maxOcc = self.timeline.maxOccZoom
      
# Draw Y legend
    i = 1
    y = self.m / 3
    pen = self.painter.pen()
    while i <= scale:
      pen.setColor(Qt.black)
      pen.setStyle(Qt.SolidLine)
      self.painter.setPen(pen)
      self.painter.drawLine(self.yLeftMargin - 3, y, self.yLeftMargin + 3, y)
      self.painter.drawText(self.paddingYText, y - 8, self.yLeftMargin - self.paddingYText * 2, 50, 0, str(maxOcc - (i - 1.0) * (maxOcc / scale)))
      pen.setColor(Qt.gray)
      pen.setStyle(Qt.DotLine)
      self.painter.setPen(pen)
      self.painter.drawLine(self.yLeftMargin + 3, y, self.ploter.width - self.m, y)
      y = (self.m / 3) + i * ((self.ploter.height - (self.m + self.m / 3)) / scale)
      i += 1

    pen.setStyle(Qt.SolidLine)
    self.painter.setPen(pen)

  def drawTimeline(self, painter, elements):
    self.painter = painter
# Find x drawing area
    xRange = (self.ploter.width - self.m - self.yLeftMargin) / self.timeline.lineHeight
# Find secs between each x hop
    if not self.timeline.selDateMin:
      self.xHop = (self.baseDateMax - self.baseDateMin) / xRange
    else:
# We are in a zoom
      self.xHop = (self.selDateMax - self.selDateMin) / xRange
# FIXME no need to set it for each line ...!
    self.timeline.xHop = self.xHop
    self.drawEverythingInX(elements)


  def drawEverythingInX(self, elements):
    if not self.timeline.selDateMin:
      timeChecked = self.baseDateMin
      limit = self.baseDateMax
    else:
      timeChecked = self.selDateMin
      limit = self.selDateMax
    while timeChecked <= limit:
      occ = self.timeline.elementsInRange(elements, timeChecked, timeChecked + self.xHop)
      if occ:
          self.drawOneLine(timeChecked, occ)
      timeChecked += self.xHop
      if self.xHop <= 0:
# FIXME set stateinfo to ("error", "Not enough different date in this node")
        return
# FIXME set stateinfo to ("result", "no problem")
    return
    
  def drawOneLine(self, timeChecked, occ):
    if not self.timeline.selDateMin:
      dateMin = self.timeline.baseDateMin
      dateMax = self.timeline.baseDateMax
      maxOcc = self.timeline.maxOcc
    else:
      dateMin = self.timeline.selDateMin
      dateMax = self.timeline.selDateMax
      maxOcc = self.timeline.maxOccZoom

    if (dateMax - dateMin) > 0:
      x = ((timeChecked - dateMin) * (self.ploter.width - self.m - self.yLeftMargin)) / (dateMax - dateMin) + self.yLeftMargin
      y = (((maxOcc - occ) * (self.ploter.height - self.m - (self.m / 3))) / maxOcc) + (self.m / 3)
      if x <= self.yLeftMargin:
          x += 3

      startY = self.ploter.height - self.m - 1
      endY = y

      if y < self.ploter.height - self.m - 1:
# Y level to show is biggest than penWidth
          startY -= 1
          endY -= 1

      if endY <= self.m / 3:
# Y level is biggest than Y max value
        endY = self.m / 3 + 2

      line = QLineF(x, startY, x, endY)

      self.painter.drawLines(line)

  def findXTime(self, x):
    self.selDateMin = self.timeline.selDateMin
    self.selDateMax = self.timeline.selDateMax
    usecX = 0
    if not self.selDateMin or not self.selDateMax:
# Click from main (original) view
      usecX = ((x - self.yLeftMargin) * (self.baseDateMax - self.baseDateMin)) / (self.ploter.width - self.m - self.yLeftMargin)
      usecX += self.baseDateMin
      if usecX < self.baseDateMin:
        usecX = self.baseDateMin
      if usecX > self.baseDateMax:
        usecX = self.baseDateMax
# Avoid microseconds
      usecStr = str(int(usecX))
      usecX = int(usecStr[:-6] + '000000')
      ret = self.timeline.fromUSec(usecX)
      return datetime(ret.year, ret.month, ret.day, ret.hour, ret.minute, ret.second, 0)
    else:
# Click already from a zoom view 
      usecX = ((x - self.yLeftMargin) * (self.selDateMax - self.selDateMin)) / (self.ploter.width - self.m - self.yLeftMargin)
      usecX += self.selDateMin
      if usecX < self.selDateMin:
        usecX = self.selDateMin
      if usecX > self.selDateMax:
        usecX = self.selDateMax
# Avoid microseconds
      usecStr = str(int(usecX))
      usecX = int(usecStr[:-6] + '000000')
      ret = self.timeline.fromUSec(usecX)
      return datetime(ret.year, ret.month, ret.day, ret.hour, ret.minute, ret.second, 0)
    return None

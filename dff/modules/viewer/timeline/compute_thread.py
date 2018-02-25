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

from PyQt4.QtCore import QString, QThread, SIGNAL, QMutex, QWaitCondition, QMutexLocker

from dff.api.types.libtypes import typeId

class WorkerThread(QThread):
  ''' Schedule things to do

  Wait all time or launch/wake other threads to recompute max amount of node to
  display with or without zoom, refresh/redraw paint area, etc. .
  '''
  def __init__(self, parent = None):
    super(WorkerThread, self).__init__(parent)
    self.mutex = QMutex()
    self.condition = QWaitCondition()
    self.restart = False
    self.abort = False
    self.timeline = parent
    self.countThread = parent.countThread
    self.populateThread = parent.populateThread
    self.maxOccThread = parent.maxOccThread
    
  def __del__(self):
    self.mutex.lock()
    self.abort = True
    self.condition.wakeOne()
    self.mutex.unlock()

    self.wait()

  def render(self):
    locker = QMutexLocker(self.mutex)
    if not self.isRunning() and not self.countThread.isRunning() and not self.populateThread.isRunning() and not self.maxOccThread.isRunning():
      self.start(QThread.LowPriority)
    else:
      self.restart = True
      self.condition.wakeOne()
      
  def run(self):
    while True:
      self.mutex.lock()
      # Fetch value from timeline
      nodeCount = self.timeline.nodeCount
      dataListsCreated = self.timeline.dataListsCreated
      if dataListsCreated:
        self.timeline.findMaxValue()
      xHop = self.timeline.xHop
      maxOcc = self.timeline.maxOcc
      self.mutex.unlock()

      if not nodeCount and not self.restart and not self.countThread.isRunning():
        self.countThread.start()
      elif nodeCount and not dataListsCreated and not self.restart and not self.populateThread.isRunning():
        self.populateThread.start()
      elif nodeCount and dataListsCreated and xHop and not maxOcc and not self.restart and not self.maxOccThread.isRunning():
        self.maxOccThread.start()
      elif nodeCount and dataListsCreated and xHop and maxOcc and not self.restart and not self.maxOccThread.isRunning():
        self.emit(SIGNAL('refresh'), True)
        
      if self.abort:
        return

      self.mutex.lock()
      if not self.restart:
        self.condition.wait(self.mutex)
      self.restart = False
      self.mutex.unlock()

class CountThread(QThread):
  ''' Detects every time attributes in children of a given node.

  '''
  def __init__(self, parent, callback):
    QThread.__init__(self)
    self.timeline = parent
    self.node = self.timeline.node
    self.nodeCount = 0
    self.timesCount = 0
    self.timeMap = self.timeline.timeMap
    self.connect(self, SIGNAL("finished()"), callback)

  def timeFound(self, timesCount, mod, key):
    try:
      if key not in self.timeMap[mod]:
        self.timeMap[mod].append(key)
    except KeyError:
      self.timeMap[mod] = [key]
    timesCount += 1
    return True, timesCount
  
  def attrRecCount(self, tab, attr, countMe, timesCount, mod = None, attrPath = []):
    """
    FIXME Use node.attributeByType ? from cpp, to bench !
    """
    for key in attr.keys():
      if attr[key] and attr[key].type() == typeId.Map:
        if mod:
          countMe, timesCount = self.attrRecCount(tab + ' ', attr[key].value(), countMe, timesCount, mod, attrPath + [key])
        else:
          countMe, timesCount = self.attrRecCount(tab + ' ', attr[key].value(), countMe, timesCount, key)
      elif attr[key] and attr[key].type() == typeId.List:
        for i in xrange(attr[key].value().size()):
          if attr[key].value()[i].type() == typeId.DateTime:
            countMe, timesCount = self.timeFound(timesCount, mod, attrPath + [key])
      elif attr[key] and attr[key].type() == typeId.DateTime:
        countMe, timesCount = self.timeFound(timesCount, mod, attrPath + [key])
    return countMe, timesCount


  def countNode(self, node):
    nodeList = node.children()
    for oneNode in nodeList:
      countMe = False
      timesCount = 0
      countMe, timesCount = self.attrRecCount('', oneNode.attributes(), countMe, timesCount)
      if countMe:
          self.nodeCount += 1
          self.timesCount += timesCount
    
  def recurse(self, node):
    if node.hasChildren():
      self.countNode(node)
    nodeList = node.children()
    for oneNode in nodeList:
      if oneNode.hasChildren():
        self.recurse(oneNode)
 
  def run(self):
    self.timeline.setStateInfo('Evaluating nodes amount')
    self.recurse(self.node)
    self.timeline.nodeCount = self.nodeCount
    self.timeline.timesCount = self.timesCount
    self.timeline.timeMap = self.timeMap

class MaxOccThread(QThread):
  ''' Find maximum amount of node from a given resolution.

  Usefull for vertical scaling.
  '''
  def __init__(self, parent, callback):
    QThread.__init__(self)
    self.timeline = parent
    parent.connect(self, SIGNAL("finished()"), callback)

  def run(self):
      self.xRange = self.timeline.xRange
      self.xHop = self.timeline.xHop
      self.baseDateMin = self.timeline.baseDateMin
      self.baseDateMax = self.timeline.baseDateMax
# Find x drawing area
      newMaxOcc = 0
      for family in self.timeline.options.configuration:
        for time in family[1]:
          timeChecked = self.baseDateMin
          if timeChecked == self.baseDateMax:
# Every nodes have the same time, setting maxOcc computing time + 100usec
            occ = self.timeline.elementsInRange(time[1][5][1], timeChecked, timeChecked + 100)
            if occ > newMaxOcc:
              newMaxOcc = occ
          while timeChecked <= self.baseDateMax:
            occ = self.timeline.elementsInRange(time[1][5][1], timeChecked, timeChecked + self.xHop)
            if occ > newMaxOcc:
              newMaxOcc = occ
            timeChecked += self.xHop
            
      self.timeline.maxOcc = newMaxOcc
      self.timeline.setStateInfo('Done - check max amount of nodes in range is ' + str(newMaxOcc) + ' nodes')

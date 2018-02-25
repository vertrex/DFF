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

from PyQt4.QtCore import QString, QThread, SIGNAL

from dff.api.types.libtypes import typeId

class DataThread(QThread):
    def __init__(self, parent, callback):
        QThread.__init__(self)
        self.timeline = parent
        self.configuration = None
        self.node = None
        self.count = 0
        parent.connect(self, SIGNAL("finished()"), callback)

    def insert(self, data, node, root, dateLimits):
        ''' List insert using dichotomy

        There is two lists, one for ordered dates, and one other for
        corresponding nodes. If several nodes have the same timestamp, they are
        registered in the same list entry in an array.
        FIXME checks bellow have to be avoided, but we must do it because extfs
        for exemple returns invalid times.
        '''
        if not data.month:
            month = 1
        else:
            month = data.month
        if not data.day:
            day = 1
        else:
            day = data.day
        data = self.timeline.toUSec(datetime(data.year, month, day, data.hour, data.minute, data.second, data.usecond))

        if not root['dates']:
            root['dates'] = [data]
            root['nodes'] = [[node.uid()]]
            dateLimits[0] = data
            dateLimits[1] = data
        else:
            iMin, iMax = 0, len(root['dates']) - 1
            iCurrent = iMax / 2
            while iMin != iMax or not iMax:
                if data == root['dates'][iCurrent]:
                    root['nodes'][iCurrent].append(node.uid())
                    break
                elif data > root['dates'][iCurrent] and iCurrent == len(root['dates']) - 1:
                    root['dates'].append(data)
                    root['nodes'].append([node.uid()])
                    dateLimits[1] = data
                    break
                elif data > root['dates'][iCurrent] and data < root['dates'][iCurrent + 1]:
                    root['dates'].insert(iCurrent + 1, data)
                    root['nodes'].insert(iCurrent + 1, [node.uid()])
                    break
                elif data < root['dates'][iCurrent] and not iCurrent:
                    root['dates'].insert(0, data)
                    root['nodes'].insert(0, [node.uid()])
                    dateLimits[0] = data
                    break
                elif data < root['dates'][iCurrent] and data > root['dates'][iCurrent - 1]:
                    root['dates'].insert(iCurrent, data)
                    root['nodes'].insert(iCurrent, [node.uid()])
                    break
                elif data > root['dates'][iCurrent]:
                    iMin = iCurrent
                    iCurrent = iCurrent + ((iMax - iCurrent) / 2)
                    if iCurrent == iMin:
                        iCurrent += 1
                elif data < root['dates'][iCurrent]:
                    iMax = iCurrent
                    iCurrent = iMin + ((iCurrent - iMin) / 2)

        return root, dateLimits


    def addNode(self, node):
        """
        TODO Make it work for VList !
        Especially take care of VMap embeded in VList.
        Also see compute_thread.CountThread.attrRecCount.
        """
        nodeList = node.children()
        for oneNode in nodeList:
          countMe = False
          attr = oneNode.attributes()
          for family in self.configuration:
            if family[0] and family[1]:
              # module name is family[0]
              for time in family[1]:
                try:
                  a = attr[family[0]].value()
                  for k in time[0]:
                    try:
                      a = a[k]
                    except IndexError:
                      break
                    except TypeError:
                      break
                    if a.type() == typeId.DateTime and a.value() != None:
                      d = a.value().asPyDateTime() 
                      if d.year == 0 and d.month == 0 and d.day == 0:
                        continue
                      try:
                          time[1][5][1], time[1][6][1] = self.insert(a.value(), oneNode, time[1][5][1], time[1][6][1])
                      except ValueError:
                          continue
                      countMe = True
                      v = a.value()
                      break
                    else:
                      a = a.value()
                except IndexError:
                  pass

          if countMe:
            self.count += 1
            if not self.count % 100:
                # XXX % 100 realy improve speed ?
                percent = (self.count * 100) / self.timeline.nodeCount
                self.timeline.setStateInfo(str(percent) + "% registering nodes dates")


    def populate(self, node):
        if node.hasChildren():
          self.addNode(node)
        nodeList = node.children()
        for oneNode in nodeList:
          if oneNode.hasChildren():
            self.populate(oneNode)


    def run(self):
      self.timeline.setStateInfo('Registering nodes dates')
      self.configuration = self.timeline.options.configuration
      self.node = self.timeline.node
      self.populate(self.node)
      self.timeline.setStateInfo('Done - ' + str(self.timeline.timesCount) + ' dates from ' + str(self.timeline.nodeCount) + ' nodes registered')

      
    def dump(self, root, dateLimits):
        current = root
        print "min:", dateLimits[0], dateLimits[0].usec, "max:", dateLimits[1], dateLimits[1].usec
        while current:
            print len(current.nodeArray), " ", current.data, current.data.usec
            current = current.next

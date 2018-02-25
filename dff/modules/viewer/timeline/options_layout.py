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

from PyQt4.QtCore import Qt, SIGNAL, QString, QRect
from PyQt4.QtGui import QWidget, QCheckBox, QHBoxLayout, QVBoxLayout, QComboBox, QLabel, QTabWidget, QGroupBox, QPushButton, QPalette, QScrollArea

from dff.api.vfs import vfs, libvfs
from dff.api.vfs.libvfs import Node, VLink
from dff.api.types.libtypes import Variant, RCVariant
from dff.api.events.libevents import event

class OptionsLayout(QTabWidget):
    ''' Manages right panel.

    Provides general informations, navigation and timestamp selection.
    Navigation allow user to zoom in timeline.
    Timestamp selection allow user to select which timestamp to display with
    which color.
    '''
    def __init__(self, parent):
        QTabWidget.__init__(self)
        self.setTabPosition(QTabWidget.East)
        self.init(parent)
        self.initShape()
        
    def init(self, parent):
	self.VFS = libvfs.VFS.Get()
        self.timeline = parent
        self.swapIndex = -1
        self.swapColor = ''
        self.metricIndex = -1
        self.configuration = []
        self.zoom = False
        self.exportedNode = None

    def initShape(self):
        self.h = QHBoxLayout()
        self.vbox = QVBoxLayout()
        self.vbox.setMargin(0)
        self.vbox.setSpacing(0)

        self.vbox.setAlignment(Qt.AlignTop)
        self.setLayout(self.vbox)

        self.infoBox = QGroupBox('Global information')
#        self.infoBox.setFlat(True)
        self.totalNodes = QLabel('No time found in nodes')
        self.startTime = QLabel('No start time')
        self.endTime = QLabel('No end time')
        
        self.navBox = QGroupBox('Navigation')
        self.selStartTime = QLabel('No selection start time')
        self.selEndTime = QLabel('No selection end time')
        
        self.buttonLayout = QHBoxLayout()
        self.zoomButton = QPushButton('Zoom')
        self.zoomButton.setEnabled(False)
        self.zoomButton.connect(self.zoomButton, SIGNAL("clicked(bool)"), self.zoomClick)
        self.dezoomButton = QPushButton('Original Size')
        self.dezoomButton.setEnabled(False)
        self.dezoomButton.connect(self.dezoomButton, SIGNAL("clicked(bool)"), self.dezoomClick)
        self.exportButton = QPushButton('Export')
        self.exportButton.setEnabled(False)
        self.exportButton.connect(self.exportButton, SIGNAL("clicked(bool)"), self.exportClick)
        self.buttonLayout.setAlignment(Qt.AlignLeft)
        self.buttonLayout.addWidget(self.zoomButton)
        self.buttonLayout.addWidget(self.dezoomButton)
        self.selectedNodes = QLabel('Nothing selected')
        
        self.infoLayout = QVBoxLayout()
        self.infoLayout.setAlignment(Qt.AlignTop)
        self.infoLayout.addWidget(self.totalNodes)
        self.infoLayout.addWidget(self.startTime)
        self.infoLayout.addWidget(self.endTime)
        self.infoBox.setLayout(self.infoLayout)

        self.navLayout = QVBoxLayout()
        self.navLayout.setAlignment(Qt.AlignTop)
        self.navLayout.addWidget(self.selStartTime)
        self.navLayout.addWidget(self.selEndTime)
        self.navLayout.addLayout(self.buttonLayout)
        self.navLayout.addWidget(self.selectedNodes)
        self.navLayout.addWidget(self.exportButton)
        self.navBox.setLayout(self.navLayout)
        
        self.familyLayout = QVBoxLayout()
        self.familyLayout.setMargin(0)
        self.familyLayout.setSpacing(0)

        self.familyWidget = QWidget()
        self.familyWidget.setLayout(self.familyLayout)

        self.familyScroll = QScrollArea()

        self.insertTab(0, self.infoBox, 'Global')
        self.insertTab(1, self.navBox, 'Navigation')
        self.insertTab(2, self.familyScroll, 'Display')

    def newInformations(self):
      if self.timeline.timesCount > 1:
        sTimes = str(self.timeline.timesCount) + ' time values'
      else:
        sTimes = 'One time value'
      if self.timeline.nodeCount > 1:
        sNodes = str(self.timeline.nodeCount) + ' nodes'
      else:
        sNodes = 'one node'
      self.totalNodes.setText(sTimes + '\n' + sNodes)
      
      if self.timeline.baseDateMin != self.timeline.dateMin:
          self.startTime.setText('From ' + str(self.timeline.fromUSec(self.timeline.baseDateMin).strftime('%d.%m.%Y %H:%M:%S')))
      if self.timeline.selDateMin:
        self.selStartTime.setText('From ' + str(self.timeline.fromUSec(self.timeline.selDateMin).strftime('%d.%m.%Y %H:%M:%S')))
      else:
        self.selStartTime.setText('No selection start time')
        
      if self.timeline.baseDateMax != self.timeline.dateMax:
        self.endTime.setText('To ' + str(self.timeline.fromUSec(self.timeline.baseDateMax).strftime('%d.%m.%Y %H:%M:%S')))
      if self.timeline.selDateMax:
        self.selEndTime.setText('To ' + str(self.timeline.fromUSec(self.timeline.selDateMax).strftime('%d.%m.%Y %H:%M:%S')))
      else:
        self.selEndTime.setText('No selection end time')
      
    def dumpOptionsConf(self):
      for family in self.configuration:
        if not family[1]:
          print family[0] + ': empty'
        else:
          print family[0] + ':'
      for time in family[1]:
        print '\t' + time[0] + ':'
        for param in time[1]:
          print '\t\t' + param[0] + ':', param[1]

    def createMetricTools(self):
      '''
      Called once countThread is over.
      '''
      if not self.configuration:
# First, create configuration dictionary
        i = 0
        for timeFamily, timeList in self.timeline.timeMap.items():
          if len(timeList):
# One sub dictionary per time family
            self.configuration.append([timeFamily, []])
            for oneMetric in timeList:
# One sub sub dictionary per family sub time
#  checked indicate if item is displayed
#  color indicate which color to use
              if i < len(self.timeline.colors):
                self.configuration[-1][1].append([oneMetric, [['checked', True],
                                                              ['color', self.timeline.colors[i][0]],
                                                              ['checkBox', None],
                                                              ['colorWidget', None],
                                                              ['colorWidgetIndex', -1],
                                                              ['orderedNodeList', {'dates':None, 'nodes':None}],
                                                              ['dateLimits', [long(0), long(0xffffffffffffffff)]],
                                                              ['mainPixmap', [True, None]],
                                                              ['zoomPixmap', [True, None]]]])
              else:
                self.configuration[-1][1].append([oneMetric, [['checked', False],
                                                              ['color', ''],
                                                              ['checkBox', None],
                                                              ['colorWidget', None],
                                                              ['colorWidgetIndex', -1],
                                                              ['orderedNodeList', {'dates':None, 'nodes':None}],
                                                              ['dateLimits', [long(0), long(0xffffffffffffffff)]],
                                                              ['mainPixmap', [True, None]],
                                                              ['zoomPixmap', [True, None]]]])

              i += 1
          else:
            self.configuration.append([timeFamily, []])

# Configuration object created, now create graphical view of it
        # self.dumpOptionsConf()
        i = 0
        for family in self.configuration:
          if family[1]:
            box = QGroupBox(family[0])
            oneTime = QVBoxLayout()
            for time in family[1]:
              hbox = QHBoxLayout()
              time[1][2][1] = QCheckBox(':'.join(time[0]))
              self.connect(time[1][2][1], SIGNAL("stateChanged(int)"), self.checkboxClick)
              time[1][3][1] = QComboBox()
              for color in self.timeline.colors:
                time[1][3][1].addItem(color[0])

              palette = time[1][2][1].palette()
              if i < len(self.timeline.colors):
                time[1][2][1].setChecked(time[1][0][1])
                # Colorize foreground
                palette.setColor(QPalette.WindowText, self.timeline.colors[i][1])
                time[1][3][1].setCurrentIndex(i)
                time[1][4][1] = i
              else:
# In case every colors are already used, don't check time (default) and don't select any color
                palette.setColor(QPalette.WindowText, Qt.gray)
                time[1][0][1] = False
                time[1][3][1].setEnabled(False)
              time[1][2][1].setPalette(palette)
              
              self.connect(time[1][3][1], SIGNAL("currentIndexChanged(const QString&)"), self.colorChange)
              hbox.addWidget(time[1][2][1])
              hbox.addWidget(time[1][3][1])
              oneTime.addLayout(hbox)
              i += 1
            box.setLayout(oneTime)

            optimum = box.minimumSizeHint()
            box.setFixedSize(optimum)
            if optimum.width() > self.familyLayout.sizeHint().width():
                geom = QRect(0, 0, optimum.width(), self.familyLayout.sizeHint().height() + optimum.height())
            else:
                geom = QRect(0, 0, self.familyLayout.sizeHint().width(), self.familyLayout.sizeHint().height() + optimum.height())
            self.familyLayout.addWidget(box)

            self.familyLayout.setGeometry(geom)
            self.familyWidget.setFixedSize(geom.width(), geom.height())
            self.familyScroll.setWidget(self.familyWidget)

          
      else:
# Configuration object already created, we are called because am item has been
#  unchecked or its color has changed.
       pass
          

    def colorChange(self, colorText):
      loop = 2
      while loop:
        i = 0
        for family in self.configuration:
          for time in family[1]:
            if time[1][3][1]:
              if QString(time[1][1][1]) != time[1][3][1].currentText() and self.swapIndex == -1 and self.metricIndex == -1 and time[1][3][1].isEnabled():
# This selection has just been changed
                self.swapColor = time[1][1][1]
                self.swapIndex = time[1][4][1]
                time[1][1][1] = str(colorText)

                #Color
                palette = time[1][2][1].palette()
                palette.setColor(QPalette.WindowText, self.timeline.colors[time[1][3][1].currentIndex()][1])
                time[1][2][1].setPalette(palette)
                
                time[1][4][1] = time[1][3][1].currentIndex()
                time[1][7][1][0] = True
                time[1][8][1][0] = True
                self.metricIndex = i
              if QString(time[1][1][1]) == colorText and self.swapIndex != -1 and self.metricIndex != i and time[1][3][1].isEnabled():
# This selection is impacted because color is the same as the one just selected
#  Changing color relaunch another signal.
                time[1][1][1] = self.swapColor
                time[1][4][1] = self.swapIndex
                time[1][3][1].setCurrentIndex(self.swapIndex)
                time[1][7][1][0] = True
                time[1][8][1][0] = True

                #Color
                palette = time[1][2][1].palette()
                palette.setColor(QPalette.WindowText, self.timeline.colors[time[1][3][1].currentIndex()][1])
                time[1][2][1].setPalette(palette)

                self.metricIndex = -1
              i += 1
        loop -= 1
#      if self.swapColor == '':
# Swap already done ; redraw
      self.timeline.updatePaintingArea()
      self.swapIndex = -1
      self.swapColor = ''
      self.metricIndex = -1

    def checkboxClick(self, newState):
      self.selectedNodes.setText('Nothing selected')
      self.zoomButton.setEnabled(False)
      self.exportButton.setEnabled(False)
      for family in self.configuration:
        for time in family[1]:
          if time[1][2][1]:
            palette = time[1][2][1].palette()
            if not time[1][2][1].checkState() and time[1][0][1]:
# This box has just been unchecked
              time[1][0][1] = False
              time[1][3][1].setEnabled(False)
              palette.setColor(QPalette.WindowText, Qt.gray)
            elif time[1][2][1].checkState() and not time[1][0][1]:
# This box has just been checked
              time[1][0][1] = True
              time[1][3][1].setEnabled(True)
# Deactivate color already used
              palette.setColor(QPalette.WindowText, self.timeline.colors[time[1][3][1].currentIndex()][1])
              time[1][1][1] = self.timeline.colors[time[1][3][1].currentIndex()][0]
              time[1][4][1] = time[1][3][1].currentIndex()
              time[1][7][1][0] = True
              time[1][8][1][0] = True
              for family2 in self.configuration:
                # sure, 2 is ugly, it is used to search color to remove
                for time2 in family2[1]:
                  if time2[1][3][1] and time2[1][3][1].isEnabled():
                    if self.timeline.colors[time2[1][3][1].currentIndex()][0] == self.timeline.colors[time[1][3][1].currentIndex()][0] and time2[1][3][1] != time[1][3][1]:
                      palette2 = time2[1][2][1].palette()
                      time2[1][0][1] = False
                      time2[1][2][1].setChecked(False)
                      time2[1][3][1].setEnabled(False)
                      palette2.setColor(QPalette.WindowText, Qt.gray)
                      time2[1][2][1].setPalette(palette2)
            time[1][2][1].setPalette(palette)
      self.timeline.updatePaintingArea()

    def zoomClick(self, clickState):
      self.timeline.maxOccZoom = 0
      rect = self.timeline.ploter.selectionRect.rect()
      newSelDateMin = self.timeline.draw.findXTime(rect.x())
      newSelDateMax = self.timeline.draw.findXTime(rect.x() + rect.width())
      self.timeline.selDateMin = self.timeline.toUSec(newSelDateMin)
      self.timeline.selDateMax = self.timeline.toUSec(newSelDateMax)
      self.newInformations()
      
      self.dezoomButton.setEnabled(True)
      self.zoomButton.setEnabled(False)
      self.exportButton.setEnabled(False)
      txt = self.selectedNodes.text().__str__()
      self.selectedNodes.setText(txt[:txt.rfind(' ')] + ' displayed')
      self.zoom = True
      self.timeline.updatePaintingArea(True)

    def dezoomClick(self, clickState):
      self.dezoomButton.setEnabled(False)
      self.zoomButton.setEnabled(False)
      self.exportButton.setEnabled(False)
      self.zoom = False
      self.timeline.selDateMin = None
      self.timeline.selDateMax = None
      self.timeline.maxOccZoom = 0
      self.newInformations()
      for family in self.configuration:
        for time in family[1]:
          if time[1][8][1]:
            time[1][8][1][0] = True
            time[1][8][1][1] = None
      self.timeline.updatePaintingArea()

    def exportClick(self, clickState):
      rect = self.timeline.ploter.selectionRect.rect()
      exportSelDateMin = self.timeline.draw.findXTime(rect.x())
      exportSelDateMax = self.timeline.draw.findXTime(rect.x() + rect.width())

      for family in self.configuration:
        for time in family[1]:
          if time[1][0][1]:
            nodes = []
            everyNodes = self.timeline.elementsInRangeToNodeList(time[1][5][1], self.timeline.toUSec(exportSelDateMin), self.timeline.toUSec(exportSelDateMax))
            for oneGroupNode in everyNodes:
                for node in oneGroupNode:
                    nodes.append(node)
            if len(nodes):
              if not self.exportedNode:
# Create /timeline if needed
                  root = vfs.vfs().getnode('/Bookmarks')
                  baseNode = Node('timeline', 0, root)
	          baseNode.__disown__()
                  baseNode.setDir()
                  e = event()
                  e.thisown = False
                  e.value = RCVariant(Variant(baseNode))
                  self.VFS.notify(e)

# Create /timeline/<ParentName>
                  self.exportedNode = Node(self.timeline.node.name(), 0, baseNode)
                  self.exportedNode.__disown__()
                  self.exportedNode.setDir()
              timeBaseName = self.exportedNode.absolute() + '/' + str(exportSelDateMin.strftime('%d.%m.%Y %H:%M:%S')) + ' to ' + str(exportSelDateMax.strftime('%d.%m.%Y %H:%M:%S'))
              timeBaseNode = vfs.vfs().getnode(timeBaseName)
              if not timeBaseNode:
# Create /timeline/<ParentName>/dateStart to dateEnd/<Module:FullTimestampAttributePath>/
                  timeBaseNode = Node(str(exportSelDateMin.strftime('%d.%m.%Y %H:%M:%S')) + ' to ' + str(exportSelDateMax.strftime('%d.%m.%Y %H:%M:%S')), 0, self.exportedNode)
                  timeBaseNode.__disown__()
                  timeBaseNode.setDir()

              baseFamilyName = timeBaseNode.absolute() + '/' + ':'.join([family[0]] + time[0])
              baseFamilyNode = vfs.vfs().getnode(baseFamilyName)
              if not baseFamilyNode:
# Create /timeline/<ParentName>/dateStart to dateEnd//<Module:FullTimestampAttributePath> if needed
                  baseFamilyNode = Node(':'.join([family[0]] + time[0]), 0, timeBaseNode)
		  baseFamilyNode.__disown__()
                  baseFamilyNode.setDir()

              for node in nodes:
# Add each node in array as child
		  l = VLink(node, baseFamilyNode)
		  l.__disown__()

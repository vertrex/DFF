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

import os

from PyQt4.QtCore import Qt, SIGNAL
from PyQt4.QtGui import QScrollBar, QAbstractSlider

class stringLFScrollBar(QScrollBar):
    def __init__(self, filesize, pagesize, bytesperline, parent):
        QScrollBar.__init__(self)
        self.init(filesize, pagesize, bytesperline, parent)
        self.initCallBacks()
        self.setValues()

    def init(self, filesize, pagesize, bytesperline, parent):
        self.filesize = filesize
        self.parent = parent
        #Initialized in Whex with LFMOD
        self.pagesize = pagesize
        self.bytesperline = bytesperline
        self.max = 0
        self.min = 0
        self.single = 1
        #Long File Mode
        self.lfmod = False
        ###### LFMOD ######
        ###################
        self.maxint = 2147483647
        self.lines = self.filesize / self.bytesperline

        self.restlines = self.filesize % self.bytesperline
        if self.isInt(self.lines):
            self.max = self.lines - 1
            self.page = self.pagesize / self.bytesperline
        else:
            self.lfmod = True
            self.max = self.maxint - 1
            self.page = self.pagesize
        ####################
        ####################

    def initCallBacks(self):
        self.connect(self, SIGNAL("sliderMoved(int)"), self.moved) 
        self.connect(self, SIGNAL("actionTriggered(int)"), self.triggered) 

    def setValues(self):
        self.setMinimum(self.min)
        self.setMaximum(self.max)
        self.setSingleStep(self.single)
        self.setPageStep(self.page)
        self.setRange(self.min, self.max)

    def isLFMOD(self):
        return self.lfmod

    def isInt(self, val):
        try:
            res = int(val)
            if res <  self.maxint:
                return True
            else:
                return False
        except ValueError, TypeError:
            return False
        else:
            return False

    # LFMOD #
    def valueToOffset(self, value):
        return ((self.filesize * value) / self.maxint)

    def offsetToValue(self, offset):
        if self.isLFMOD():
            return ((self.maxint * offset) / self.filesize)
        else:
            return (offset / self.bytesPerLine)


########################################
#          Navigation Operations       #
########################################


    def triggered(self, action):
        if action in [QAbstractSlider.SliderSingleStepAdd,
                      QAbstractSlider.SliderPageStepAdd]:
            add = self.sliderPosition() - self.value()
            v = self.value() + add
            self.moved(v)
        elif action in [QAbstractSlider.SliderSingleStepSub,
                        QAbstractSlider.SliderPageStepSub]:
            sub = self.value() - self.sliderPosition()
            v = self.value() - 1
            self.moved(v)

    def moved(self, value):
        if self.isLFMOD():
            if value <= self.max:
                offset = (self.filesize * value) / self.maxint
                self.parent.readBuffer(offset)
        else:
            if value <= self.max:
                if value == self.max:
                    offset = self.filesize - (5 * self.bytesperline)
                else:
                    offset = value * self.bytesperline
                self.parent.readBuffer(offset)

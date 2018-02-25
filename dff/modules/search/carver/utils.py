# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
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
from PyQt4.QtGui import *
from PyQt4.QtCore import *

class QFFSpinBox(QAbstractSpinBox):
    def __init__(self, parent=None):
        QAbstractSpinBox.__init__(self)
        self.init(parent)
        self.initEdit()

    def init(self, parent):
        #Variables
        self.parent = parent
        self.__minimum = 0
        self.__maximum = 0
        self.__range = 0
        self.__value = 0
        self.__singleStep = 0
        #Functions
        self.setWrapping(True)
#        self.setEnabled(True)

    def initEdit(self):
        self.__edit = self.lineEdit()
        self.__edit.connect(self.__edit, SIGNAL("editingFinished()"), self.editChanged)
#        self.setLineEdit(self.__edit)

    def stepEnabled(self):
        if self.wrapping():
            if self.__value == self.__minimum:
                return self.StepEnabled(QAbstractSpinBox.StepUpEnabled)
            elif self.__value == self.__maximum:
                return self.StepEnabled(QAbstractSpinBox.StepDownEnabled)
            else:
                return self.StepEnabled(QAbstractSpinBox.StepUpEnabled | QAbstractSpinBox.StepDownEnabled)        

    def maximum(self):
        return self.__maximum

    def minimum(self):
        return self.__minimum

    def setMaximum(self, max):
        self.__maximum = max

    def setMinimum(self, min):
        self.__minimum = min

    def setSingleStep(self, step):
        self.__singlStep = step

    def setRange(self, range):
        self.__range = range

    def setValue(self, value):
        self.__value = value
        self.refreshEdit(value)

    def value(self):
        return self.__value

    def singleStep(self):
        return self.__singleStep

    def maximum(self):
        return self.__maximum

    def minimum(self):
        return self.__minimum

    def stepBy(self, step):
        if step < 0:
            if self.__value > self.__minimum:
                self.__value -= 1
                self.refreshEdit(self.__value)
        else:
            if self.__value < self.__maximum:
                self.__value += 1
                self.refreshEdit(self.__value)

    def refreshEdit(self, value):
        self.__edit.clear()
        cvalue = "%.1d" % value
        self.__edit.insert(cvalue)

    def editChanged(self):
        value = self.__edit.text()
        lvalue = value.toULongLong()
        if lvalue[1]:
            if (lvalue[0] <= self.__maximum) and (lvalue[0] >= self.__minimum):
                self.__value = lvalue[0]
                self.refreshEdit(lvalue[0])
            else:
                self.refreshEdit(self.__value)
        else:
            self.refreshEdit(self.__value)

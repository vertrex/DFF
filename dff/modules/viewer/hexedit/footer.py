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
from PyQt4.QtCore import QString, Qt, SIGNAL
from PyQt4.QtGui import QWidget, QTabWidget

from sectorView import *
from bytePresence import *

class footer(QTabWidget):
    def __init__(self, parent):
        QTabWidget.__init__(self)
        self.init(parent)
        self.initShape()

    def init(self, parent):
        self.heditor = parent

        self.setTabPosition(QTabWidget.East)

    def initShape(self):
        #Add Value tab
        self.sectors = sectorDisplay(self.heditor)
        self.pixel = bytePresence(self.heditor)

        self.insertTab(0, self.sectors, "Pages")
        self.insertTab(1, self.pixel, "Pixel")

#        self.insertTab(1, self.selected, "Values")


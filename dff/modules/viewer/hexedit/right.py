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
from PyQt4.QtCore import QString, Qt, SIGNAL
from PyQt4.QtGui import QWidget, QFont, QColor, QTabWidget

from dff.modules.hexedit.search import *
from dff.modules.hexedit.decodeValues import *
from dff.modules.hexedit.navigation import *

from dff.modules.hexedit.options import *
from dff.modules.hexedit.goto import *

class righTab(QTabWidget):
    def __init__(self, parent):
        QTabWidget.__init__(self)
        self.init(parent)
        self.initShape()

    def init(self, parent):
        self.heditor = parent

    def initShape(self):
        #Add Value tab
        self.setTabPosition(QTabWidget.East)

        self.decode = decodeValues(self.heditor)
        self.search = search(self.heditor)
        self.goto = goto(self.heditor)
        self.options = options(self.heditor)

        self.insertTab(0, self.decode,"Decode")
        self.insertTab(1, self.search, QIcon(":hex_search.png") ,"Search")
        self.insertTab(2, self.goto, "Goto")
        self.insertTab(3, self.options, QIcon(":hex_opt.png"), "Options")

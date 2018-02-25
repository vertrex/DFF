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
#  Jeremy MOUNIER <jmo@digital-forensic.org>
from PyQt4 import QtCore, QtGui
from PyQt4.QtGui import QLineEdit, QHBoxLayout, QWidget
from PyQt4.QtCore import QString, SIGNAL, Qt, QSize

from dff.api.gui.widget.search.search_widget import CustomFiltersTable

from dff.ui.gui.resources.ui_filter_bar import Ui_filterBar

class FilterBar(Ui_filterBar, QWidget):
    def __init__(self, parent = None):
        super(QWidget, self).__init__(parent)
        self.setupUi(self)
        self.activated = False
        self.parent = parent
        self.custom = CustomFiltersTable(self)
        self.custom.setWindowFlags(Qt.Popup)
        self.connect(self.showFilters, SIGNAL("clicked(bool)"), self.editFilters)
        self.connect(self.execFilter, SIGNAL("clicked(bool)"), self.runFilter)
        
    def buildQuery(self):
        query = ""
        if self.filterEdit.text() != "":
            query += "(name == w(\"" + str(unicode(self.filterEdit.text()).encode('utf-8')) + "\"))"
        else:
            return None
        return query

    def runFilter(self):
        query = self.buildQuery()
        if query != None:
            self.parent.currentView().launchFilter(query)

    def editFilters(self):
        self.custom.setFixedWidth(self.filterEdit.width())
        self.custom.move(self.filterEdit.mapToGlobal(self.filterEdit.rect().bottomLeft()))
        self.custom.show()

    def autoEnabled(self):
        return self.autoApply.isChecked()
    
    def initStyleSheets(self):
        self.founded = "QLineEdit {background: #eeeeee;}"
        self.notfounded = "QLineEdit {background: #000000;}"

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
import os

from PyQt4 import QtCore, QtGui
from PyQt4.QtGui import QWidget, QTableWidgetItem, QFileDialog, QDialog, QVBoxLayout, QDialogButtonBox
from PyQt4.QtCore import QVariant, SIGNAL,Qt, SLOT, QEvent, QString, QSize

from dff.api.filters.libfilters import QueryFlags, AttributeFactory, Filter, DictRegistry, FileDictionnary

from dff.ui.gui.resources.ui_dico_manager import Ui_dicoManager

class DicoManager(QWidget, Ui_dicoManager):
    def __init__(self):
        QWidget.__init__(self)
        self.setupUi(self)
        self.manager = DictRegistry.instance()
        self.initConnexions()
        self.dicos.horizontalHeaderItem(1).setSizeHint(QSize(200, 25));

    def initConnexions(self):
        self.connect(self.addDico, SIGNAL("clicked()"), self.addDictionnary)
        self.connect(self.rmDico, SIGNAL("clicked()"), self.removeDictionnary)
        
    def addDictionnary(self):
        fn = QFileDialog.getOpenFileName(self, self.tr("Select your dictionnary"), os.path.expanduser('~'))
        if fn != "":
            ufn = str(unicode(fn).encode('utf-8'))
            dicname = self.autoDicName(ufn)
            if dicname != None:
                currow = self.dicos.rowCount()
                self.dicos.setRowCount(currow + 1)
                item = QTableWidgetItem(QString.fromUtf8(ufn))
                item.setFlags(Qt.ItemIsUserCheckable|Qt.ItemIsEnabled|Qt.ItemIsSelectable)
                item.setCheckState(Qt.Unchecked)
                self.dicos.setItem(currow, 0, item)
                name = QTableWidgetItem(QString.fromUtf8(dicname))
                name.setFlags(Qt.ItemIsEnabled|Qt.ItemIsSelectable)
                self.dicos.setItem(currow, 1, name)
                dict_ = FileDictionnary(ufn)
                dict_.thisown = False
                try:
                    self.manager.add(dicname, dict_)
                except RuntimeError:
                    print "Error adding new dictionnary"

    def autoDicName(self, path):
        try:
            filename = os.path.split(path)[1]
            sdic = filename.split('.')[0]
            return sdic
        except:
            print "error getting auto dictionnary name"
            return None

    def populateList(self):
        dicts = self.manager.dictionnaries()
        currow = 0
        for _dict in dicts.iterkeys():
            self.dicos.setRowCount(currow + 1)
            item = QTableWidgetItem(QString.fromUtf8(dicts[_dict].fileName()))
            item.setFlags(Qt.ItemIsUserCheckable|Qt.ItemIsEnabled|Qt.ItemIsSelectable)
            item.setCheckState(Qt.Unchecked)
            self.dicos.setItem(currow, 0, item)
            name = QTableWidgetItem(QString.fromUtf8(_dict))
            name.setFlags(Qt.ItemIsEnabled|Qt.ItemIsSelectable)
            self.dicos.setItem(currow, 1, name)
            currow += 1

    def removeDictionnary(self):
        row = self.dicos.currentRow()
        if row >= 0:
            try:
                name = self.dicos.item(row, 1)
                self.manager.remove(str(unicode(name.text()).encode('utf-8')))
                self.dicos.removeRow(row)
            except RuntimeError as e:
                print str(e)
                print "Error removing dictionnary"
            except TypeError as e:
                print str(e)

    def selectedDictionnaries(self):
        # Return checked dictionnaries
        dicnames = []
        for row in xrange(0, self.dicos.rowCount()):
            item = self.dicos.item(row, 0)
            if item.checkState() == Qt.Checked:
                itemname = self.dicos.item(row, 1)
                dicname = str(unicode(itemname.text()).encode('utf-8'))
                dicnames.append(dicname)
        return dicnames

    def selectedDicoNames(self):
        dicnames = self.selectedDictionnaries()
        dics = []
        if len(dicnames) > 0:
            for d in dicnames:
                ret = ":" + d
                dics.append(ret)
            return dics
        else:
            return None

class DicoDialog(QDialog):
    def __init__(self, parent):
        super(QDialog, self).__init__()
        self.parent = parent
        self.vbox = QVBoxLayout()
        self.manager = DicoManager()
        self.manager.populateList()
        self.vbox.addWidget(self.manager)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok|QDialogButtonBox.Cancel)
        self.vbox.addWidget(buttons)
        self.setLayout(self.vbox)
        self.connect(buttons, SIGNAL("accepted()"), self.accept)
        self.connect(buttons, SIGNAL("rejected()"), self.reject)
        self.selectedDicos = None

    def reject(self):
        QDialog.reject(self)

    def accept(self):
        QDialog.accept(self)

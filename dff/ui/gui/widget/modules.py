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
#  Solal Jacob <sja@digital-forensic.org>
#  Jeremy MOUNIER <jmo@digital-forensic.org>
#

from PyQt4.QtGui import QAction, QApplication, QDockWidget, QIcon,  QHBoxLayout, QPushButton, QTabWidget, QTreeWidget, QTreeWidgetItem, QWidget, QDialog, QGridLayout, QLabel, QComboBox, QMessageBox
from PyQt4.QtCore import QRect, QSize, Qt, SIGNAL, QEvent

from dff.api.loader import loader 
from dff.api.taskmanager.taskmanager import TaskManager 
from dff.api.types.libtypes import typeId

from dff.ui.gui.utils.utils import Utils
from dff.ui.gui.resources.ui_modules import Ui_Modules

class Modules(QTreeWidget, Ui_Modules):
    def __init__(self, parent):
        QTreeWidget.__init__(self, parent)
        self.name = "Modules"
        self.tm = TaskManager()
        self.loader = loader.loader()
        self.setupUi(self)
        self.initTreeModule()

    def initTreeModule(self):
        self.itemModuleDic = dict()
	self.itemListArgDic = dict()
	self.itemArgDic = dict()
	self.itemListResDic = dict()
	self.itemResDic = dict()

    def LoadInfoModules(self):
        modules = self.loader.modules
        for mod in modules :
	  try  :
	    itemModule = self.itemModuleDic[mod]
	  except KeyError:
	    itemModule = QTreeWidgetItem(self)
	    self.itemModuleDic[mod] = itemModule
	    itemModule.setText(0, str(mod))
	    itemConfig = QTreeWidgetItem(itemModule)
	    itemConfig.setText(0, "Config")
            conf = modules[mod].conf
            args = conf.arguments()
	    for arg in args:
	        itemConfKey = QTreeWidgetItem(itemConfig) 
	        itemConfKey.setText(0, "var")
	        itemConfKey.setText(1, arg.name())
	        itemConfKey.setText(4, typeId.Get().typeToName(arg.type()))
	        if len(arg.description()):
                    itemConfKey.setText(3, arg.description())
                parameters = arg.parameters()
                if len(parameters):
                    itemConfKey.setText(2, str(parameters))
	          		    	 	    		
    def deleteInfoModule(self):
	self.clear()

    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
        else:
            QTreeWidget.changeEvent(self, event)

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
#  Francois Percot <percot@gmail.com>
# 

from PyQt4.QtGui import QAction, QIcon
from PyQt4.QtCore import SIGNAL
from utils import Utils

# XXX Move to action after complete portage
class newAction(QAction):
    def __init__(self, parent, mainWindow, text, type, icon = None):
        super(newAction, self).__init__(mainWindow)
        self.__mainWindow = mainWindow
        self.type = type
        self.parent = parent
        if icon:
          self.setIcon(QIcon(icon))
        self.hasOneArg = Utils.hasOneNodeArg(text, type)
        if text <> 0 :
            self.setText(str(text))
        self.connect(self, SIGNAL("triggered()"), self.sendSignal)
        self.connect(self, SIGNAL("launchScript"), self.__mainWindow.applyModule)
        self.connect(self, SIGNAL("execModule"), Utils.execModule)
    
    def sendSignal(self):
        if self.hasOneArg and (self.parent.model.currentNode() != None) :
            selection = [self.parent.model.currentNode()]
            self.emit(SIGNAL("execModule"), self.text(), self.type, self.hasOneArg, selection)
        else :
            selection = self.parent.model.selection.getNodes()
            if len(selection) == 0:
                selection = [self.parent.model.currentNode()]
            # XXX here give list ?
            try :
                self.emit(SIGNAL("launchScript"), self.text(),  self.type, selection)
            except TypeError:	
                self.emit(SIGNAL("launchScript"), self.text(),  self.type, None)


class Action(QAction):
    def __init__(self, parent, mainWindow, text, type, icon = None):
        super(Action, self).__init__(mainWindow)
        self.__mainWindow = mainWindow
        self.type = type
        self.parent = parent
        if icon:
          self.setIcon(QIcon(icon))
        self.hasOneArg = Utils.hasOneNodeArg(text, type)
        if text <> 0 :
            self.setText(str(text))
        self.connect(self, SIGNAL("triggered()"), self.sendSignal)
        self.connect(self, SIGNAL("launchScript"), self.__mainWindow.applyModule)
        self.connect(self, SIGNAL("execModule"), Utils.execModule)
    
    def sendSignal(self):
        if self.hasOneArg and self.parent.callbackSelected :
            self.emit(SIGNAL("execModule"), self.text(), self.type, self.hasOneArg, self.parent.callbackSelected())
        else :
            try :
                self.emit(SIGNAL("launchScript"), self.text(),  self.type, self.parent.callbackSelected())
            except TypeError:	
                self.emit(SIGNAL("launchScript"), self.text(),  self.type, None)

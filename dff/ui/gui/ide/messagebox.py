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
from PyQt4.QtCore import *
from PyQt4.QtGui import *

class MessageBoxWarningSave(QMessageBox):
    def __init__(self,  parent,  message):
        super(MessageBoxWarningSave,  self).__init__(parent)
        self.ide = parent
        self.message = message
        self.g_display()
        
    def g_display(self):
        self.setText(self.message)
        self.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        self.setIcon(QMessageBox.Warning)
        
    def accept(self):
        self.ide.saveasactBack()
        self.destroy()
        
    def reject(self):
        self.destroy()

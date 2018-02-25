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
#

from PyQt4.QtGui import QStackedWidget, QIcon, QPixmap, QApplication, QWidget, QToolBar, QVBoxLayout
from PyQt4.QtCore import QRect, QSize, Qt, SIGNAL, QEvent

from dff.api.loader.loader import loader

class Preview(QWidget):
    def __init__(self, parent):
	QWidget.__init__(self, parent)
        self.layout = QVBoxLayout(self)
	self.layout.setSpacing(0)
        self.layout.setContentsMargins(0, 0, 0, 0)
	self.stack = QStackedWidget(self)
        self.toolBar = QToolBar(self)
	self.connect(self.toolBar, SIGNAL('actionTriggered(QAction*)'), self.clicked)
        self.layout.addWidget(self.toolBar)
        self.layout.addWidget(self.stack)
        self.setLayout(self.layout)
        self.__mainWindow = parent        
        self.name = "Preview"
        self.loader = loader()
	self.lmodules = self.loader.modules
	void = QWidget()
	self.previousWidget = void 
	self.stack.addWidget(void)
        self.setWindowIcon(QIcon(QPixmap(":viewer.png")))
        self.retranslateUi(self) 
        self.previousNode = None
        self.currentNode = None 
	self.mustUpdate = True

    def updateCheckState(self, state):
       self.mustUpdate = state 
       if state:
	 self.setDisabled(False)
	 self.update(self.currentNode)
       else:
	 self.setDisabled(True)

    def clicked(self, action):
       if self.isVisible() and self.mustUpdate and self.currentNode and self.currentNode.size():
 	 self.display(self.currentNode, str(action.text()))

    def update(self, node):
       if self.isVisible() and self.mustUpdate and node and node.size():
         if self.previousNode == node.uid():
	   return
         else:
	   self.toolBar.clear()
	   self.toolBar.addAction("hexadecimal")
	   self.previousNode = node.uid()
	   self.currentNode = node
           previewModules = [] 
           compat = node.compatibleModules()

           if len(compat):
   	     for module in compat:
	       if "Viewers" in self.lmodules[module].tags:
	        previewModules.append(module)
		self.toolBar.addAction(module)
	    
           if not len(previewModules):
	     self.display(node, "hexadecimal")
           else:
	     self.display(node, str(previewModules[0]))
       elif node and node.size():
	 self.currentNode = node

    def display(self, node, previewModule):
       try:
	   args = {}
	   args["file"]  = node
 	   args["preview"] = True
	   conf = self.loader.get_conf(previewModule)
  	   genargs = conf.generate(args)
	   if self.previousWidget:
  	     self.stack.removeWidget(self.previousWidget)
	     self.previousWidget.close()
	     del self.previousWidget
	   self.previousWidget = self.lmodules[previewModule].create()
	   self.previousWidget.start(genargs)
	   self.previousWidget.g_display()
           if str(self.previousWidget).find("player.PLAYER") == -1:
             self.previousWidget.setAttribute(Qt.WA_DeleteOnClose)
	   self.stack.addWidget(self.previousWidget)
       except:
         pass

    def retranslateUi(self, widget):
       widget.setWindowTitle(QApplication.translate("Preview", "Preview", None, QApplication.UnicodeUTF8))

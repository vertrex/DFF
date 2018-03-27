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
#  Frederic Baguelin <fba@digital-forensic.org>
# 

from PyQt4.QtGui import QLabel, QApplication, QFontMetrics, QSizePolicy
from PyQt4.QtCore import QString, SIGNAL, Qt

from dff.api.vfs.libvfs import VLink, VFS

class LinkLabel(QLabel):
    def __init__(self, parent=None):
      QLabel.__init__(self, parent)
      self.setTextInteractionFlags(Qt.LinksAccessibleByMouse|Qt.TextSelectableByMouse)
      self.setAlignment(Qt.AlignLeft)
      sizePolicy = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
      sizePolicy.setHorizontalStretch(0)
      sizePolicy.setVerticalStretch(0)
      self.setSizePolicy(sizePolicy)
      self.setTextFormat(Qt.RichText)
      self.__node = VFS.Get().GetNode("/")
      self.connect(self, SIGNAL("linkActivated(QString)"), self.goto)

    def setLink(self, node, width=-1):
      if node is None:
        return
      if isinstance(node, VLink):
        self.__node = node.linkNode()
      else:
        self.__node = node
      elided_text = QFontMetrics(self.font()).elidedText(QString.fromUtf8(self.__node.absolute()), Qt.ElideLeft, self.width())
      self.setText('<a href="' + QString.fromUtf8(self.__node.path()) + '" style="color: blue">'+ elided_text +' </a>')
      self.setToolTip(QString.fromUtf8(self.__node.absolute()))

    def goto(self, path):
      if path and self.__node:
        QApplication.instance().mainWindow.addNodeBrowser(self.__node.parent(), self.__node)

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

from PyQt4.QtGui import QTextEdit
from PyQt4.QtCore import SIGNAL

class TextEdit(QTextEdit):
  def __init__(self, proc):
      QTextEdit.__init__(self)
      self.setReadOnly(1)
      self.icon = 0
      self.name = proc.name
      self.type = "autogen"
      self.proc = proc 
      proc.widget = self
      self.connect(self, SIGNAL("puttext"), self.puttext)

  def puttext(self, text):
      if text:
        self.append(text)		

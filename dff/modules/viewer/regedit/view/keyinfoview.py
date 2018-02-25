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

from PyQt4.QtCore import SIGNAL
from PyQt4.QtGui import QLabel

import datetime

class KeyInfoView(QLabel):
  def __init__(self, parent, model):
    QLabel.__init__(self, parent)
    self.setMaximumHeight(30)
    self.__model = model
    self.connect(self.__model, SIGNAL("keyItemSelected"), self.keyChanged)

  def keyChanged(self, keyitem):
    rhive = keyitem.getHive()
    path = keyitem.path
    hive = rhive.hive
    if len(path) == 1:
        key = hive.root
    else:
        key = hive.subtree(path[1:]).current_key()
    abspath = key.name
    pitem = keyitem.parent()
    while pitem != None:
        abspath = pitem.text() + "\\" + abspath
        pitem = pitem.parent()
    modified =  str(datetime.datetime.fromtimestamp(key.modified))
    self.setText(abspath + "\n" + "Last modified: " + modified)
    del hive
    del rhive

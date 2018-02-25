# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
# 
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

from PyQt4.QtCore import SIGNAL, QIODevice 

class IODevice(QIODevice):
   def __init__(self, node):
      super(QIODevice, self).__init__()
      self.connect(self, SIGNAL('aboutToClose'), self.__close)	
      self.file = None
      self.node = node    

   def __del__(self):
      if self.file:
        self.__close()
 
   def open(self, mode = None):
     try :
       self.file = self.node.open()
       self.setOpenMode(QIODevice.ReadOnly | QIODevice.Unbuffered)
       return True
     except (AttributeError, IOError):
       return False 

   def seek(self, pos):
     if self.file :	
       n = self.file.seek(pos)
       if n == pos:
         return True
     return False

   def __close(self):
      self.file.close()
      self.file = None 
      return True  

   def readData(self, size):
      if self.file:
        return self.file.read(size)
      return "" 

   def pos(self):
      if self.file:
        return long(self.file.tell())
      return 0

   def isSequential(self):
      return False

   def size(self):
      return long(self.node.size())

   def reset(self):
      if self.file:
        self.file.seek(0)
        return True
      return False

   def atEnd(self):
      if self.file:
        if self.file.tell() >= self.node.size():
  	  return True
      return False  



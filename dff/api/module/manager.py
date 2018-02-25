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

class ModuleProcessusManager():
  __instance = None
  class __ModuleProcessusManager():
    def __init__(self):
      self.handlers = {}	

    def register(self, handler):
      self.handlers[handler.name] = handler
      return True

    def update(self, processus):
      try:
        self.handlers[processus.name].update(processus)
      except KeyError:
	pass

    def get(self, moduleName):
      try:
        return self.handlers[moduleName]
      except KeyError:
        return None

  def __init__(self):
     if ModuleProcessusManager.__instance is None:
       ModuleProcessusManager.__instance = ModuleProcessusManager.__ModuleProcessusManager()
  
  def __setattr__(self, attr, value):
     setattr(self.__instance, attr, value)

  def __getattr__(self, attr):
     return getattr(self.__instance, attr)


class ModuleProcessusHandler():
   def __init__(self, name):
     self.name = name
     ModuleProcessusManager().register(self)

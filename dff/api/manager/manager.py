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
#  Solal Jacob <sja@digital-forensic.org>


from dff.api.destruct import *
from dff.api.types import libtypes
from dff.api.events import libevents
from dff.api.search import libsearch
from dff.api.datatype import libdatatype
from dff.api.exceptions import libexceptions
from dff.api.vfs import vfs, libvfs
from dff.api.loader import loader
from dff.api.taskmanager.taskmanager import TaskManager
from dff.api.taskmanager.scheduler import sched 
from dff.api.taskmanager.processus import Processus
from dff.api.datatype.magichandler import * 
from dff.api.tree import libtree

class ApiManager():
   class __ApiManager():
      def __init__(self):
         self.vfs = vfs.vfs
         self.TaskManager = TaskManager
         self.loader = loader.loader
         self.Path = libtypes.Path

   __instance = None

   def __init__(self):
      if ApiManager.__instance is None:
         ApiManager.__instance = ApiManager.__ApiManager()
 
   def __setattr__(self, attr, value):
      setattr(self.__instance, attr, value)

   def __getattr__(self, attr):
      return getattr(self.__instance, attr) 

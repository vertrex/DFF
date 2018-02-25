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
import sys, inspect, os

from PyQt4.QtGui import QApplication, QTextEdit, QTextCursor , QPalette, QColor, QBrush, QHBoxLayout, QIcon
from PyQt4.QtCore import Qt, QString, QThread, QSemaphore, SIGNAL, QObject

from dff.api.loader import loader
from dff.api.taskmanager.processus import ProcessusManager
from dff.api.taskmanager.scheduler import sched

class RedirectWrite(QThread):
   __parent = None
   def __init__(self, parent, out):
     QThread.__init__(self)
     RedirectWrite.__parent = parent
     self.sout = out 
     self.processusManager = ProcessusManager()

   def run(self):
      self.exec_()

   def write(self, text):
	frame = inspect.currentframe().f_back
	if frame:
          fname = frame.f_globals['__name__'] if frame.f_globals.has_key("__name__") else None
 	  for (nparent, lframe, ismod) in self.lparent:
	    if fname in lframe:
	      nparent.emit(SIGNAL(nparent.sig), text)
	      del frame
	      return
	  if fname in self.loader.modules:
              try:
		inst = frame.f_locals['self']
		for proc in self.processusManager:
		  if proc.inst == inst:
		    if not "thread" in proc.exec_flags:
		      for (nparent, lframe, ismod) in self.lparent:
		        if ismod:
	                  nparent.emit(SIGNAL(nparent.sig), text)
		          del frame
		          return
		    else:
		        proc.stream.put(text)
			return  
              except KeyError:
                pass 
        if frame:
           del frame
        if self.ioOut != None and self.sout == 'out':
	    self.ioOut.emit(SIGNAL(self.ioOut.sigout), text)
        elif self.ioOut != None and self.sout == 'err':
	    self.ioOut.emit(SIGNAL(self.ioOut.sigerr), text)
	elif self.sout == 'err':
	  sys.__stderr__.write(text)
        else :
          sys.__stdout__.write(text)

   def __getattr__(self, attr):
     return getattr(RedirectWrite.__parent, attr)    

class RedirectIO():
   class __RedirectIO():
     def __init__(self, IOout = None, debug = False):
       self.lparent = []
       self.debug = debug
       self.oldstdout = sys.__stdout__
       self.oldstderr = sys.__stderr__
       self.ioOut = IOout
       self.processusManager = ProcessusManager()
       self.loader = loader.loader()
       if not self.debug:
         sys.stdout = RedirectWrite(self, 'out')
         sys.stderr = RedirectWrite(self, 'err')
       self.write = sys.stdout.write      
 
     def addparent(self, nparent, lframe, ismod = False):
       self.lparent += [(nparent, lframe, ismod)]

   __instance = None
   
   def __init__(self, IOout = None, debug = False):
     if RedirectIO.__instance is None:
	RedirectIO.__instance = RedirectIO.__RedirectIO(IOout, debug)
     if IOout:
	RedirectIO.__instance.ioOut = IOout    
 
   def __setattr__(self, attr, value):
	setattr(self.__instance, attr, value)
  
   def __getattr__(self, attr):
	return getattr(self.__instance, attr)


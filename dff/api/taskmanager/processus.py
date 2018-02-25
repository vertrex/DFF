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

import threading, time, sys, traceback
from Queue import Queue

from dff.api.vfs import vfs
from dff.api.vfs.libvfs import Node, VLink
from dff.api.module.module import Script 
from dff.api.types.libtypes import VMap, Variant
from dff.api.taskmanager.scheduler import sched 
from dff.api.module.manager import ModuleProcessusManager
from dff.ui.console.utils import VariantTreePrinter

class ProcessusManager(object):
  """This class store list of launched processus, and provide way to add or 
  list them."""
  __instance = None
  def __init__(self):
     if ProcessusManager.__instance is None:
       ProcessusManager.__instance = ProcessusManager.__ProcessusManager()

  def __setattr(self, attr, value):
     setattr(self.__instance, attr, value)

  def __getattr__(self, attr):
     return getattr(self.__instance, attr)

  def __iter__(self):
     if ProcessusManager.__instance is not None:
       for processus in ProcessusManager.__instance:
         yield processus

  def __len__(self):
     if ProcessusManager.__instance:
       return len(__instance)
     else:
       return 0

  def __getitem__(self, item):
     if ProcessusManager.__instance:
       return ProcessusManager.__instance[item]
     else:
       return None
  

  class __ProcessusManager(object):
    def __init__(self):
       self.processus = []
       self.dprocessus = {}
       self.lock = threading.Lock()
       self.npid = 0
	
    def pid(self, pid):
       """Return processus by pid"""
       self.lock.acquire()
       proc = self.processusID[pid]
       self.lock.release()
       return proc

    def exist(self, module, argument):
       """Search is a processus was created from the given module and argument.
 	  Return True or False.
       """
       try:
         self.lock.acquire()
	 procList = self.dprocessus[module.name]
	 for proc in procList:
	    flag = 1
	    procArgs = proc.args
            if isinstance(procArgs, VMap):
	      for k, v in procArgs.iteritems():
	        try :
                   #XXX list of node == list of node ?
                   arg = argument[k].value()
                   val  = v.value()
                   if isinstance(arg, VLink):
                     arg = arg.linkNode().this
                   elif isinstance(arg, Node):
                     arg = arg.this
                   if isinstance(val, Node):
                     val = val.this
                   elif isinstance(val, VLink):
                     val = val.linkNode().this
		   if str(val) != str(arg):
		    flag = 0
		    break
	        except (IndexError, KeyError, TypeError):
		  flag = 0
		  break
              if flag == 1:
                  self.lock.release()
		  return True 
	    else:
                print "vfs.taskmanager.exist type mismatch you should apply SWIG patch. Processus args " + str(type(procArgs)) + ' module ' + str(module.name) 
         self.lock.release()
	 return False	   
       except KeyError:
	  pass
       self.lock.release()
       return False 

    def fsobj(self, fsobj):
       """Get processus by fsobj
       """
       self.lock.acquire()
       try:
         procList = self.processus
         for proc in procList:
           try:
             if proc.this == fsobj.this:
               self.lock.release()
               return proc
           except:
             pass
       except KeyError:
         pass
       self.lock.release()
       return None
       
    def fsobjArgumentsByType(self, fsobj, argumentType):
       proc = self.fsobj(fsobj)
       match = []
       if proc:
         arguments = proc.mod.conf.argumentsByType(argumentType)
         for argument in arguments:
           try:
             arg = proc.args[argument.name()]  
             match.append(arg)
           except KeyError:
             pass
       return match

    def create(self, mod, args, exec_flags):
       self.lock.acquire()
       proc = Processus(mod, self.npid, None, exec_flags)
       self.__addProcessus__(proc)
       self.npid += 1 
       self.lock.release()
       return proc

    def singleCreate(self, mod, args, exec_flags):
       self.lock.acquire()
       try:
	  proc = self.dprocessus[mod.name][0]
          self.lock.release()
	  return proc
       except KeyError:
          proc = Processus(mod, self.npid, None, exec_flags)
          self.__addProcessus__(proc)
          self.npid += 1 
          self.lock.release()
          return proc
 
    def __addProcessus__(self, processus):
       """Add a newly created processus to the processus list"""
       self.processus.append(processus)     
       try:
         self.dprocessus[processus.mod.name].append(processus)
       except KeyError:
	 self.dprocessus[processus.mod.name] = [processus]

    def remove(self, processus):
       """Remove a processus from the list"""
       self.lock.acquire()
       self.dprocessus[processus.mod.name].remove(processus)
       self.processus.remove(processus)	
       self.lock.release()

    def module(self, module):
	"""Return processus by module"""
	try:
	  self.lock.acquire()
	  proc =  self.dprocessus[module.name]		
          self.lock.release()
          return proc
	except KeyError:
          self.lock.release()
	  return None 

    def __iter__(self):
       for processus in self.processus:
	  yield processus

    def __len__(self):
       return len(self.processus)

    def __getitem__(self, processus):
       self.lock.acquire()
       proc =  self.processus[processus]
       self.lock.release()
       return proc

class Processus(Script):
  def __init__(self, mod, pid, args, exec_flags):
    self.vfs = vfs.vfs()
    self.mod = mod
    self.inst = mod.create()
    self.exec_flags = exec_flags
    self.state = "wait"
    self.pid =  pid 
    self.args = args
    self.stream = Queue()
    self.event = threading.Event()
    self.vtreeprinter = VariantTreePrinter()
    self.timestart = 0
    self.timeend = 0
    self.streamOut = None
    self.error_result = '' 
    self.lock = threading.Lock()
    self.lock.acquire()
    self.launchCount = 0  
    self.lock.release()

  def launch(self, args):
    self.state = "Running"
    self.lock.acquire()
    self.launchCount += 1
    self.timestart = time.time()
    self.timeend = 0
    self.lock.release()
    try :
      self.args = args 
      self.start(args)
      ModuleProcessusManager().update(self)
      try :
        if "gui" in self.exec_flags:
          if "gui" in self.mod.flags:
             for func in sched.event_func["add_qwidget"]:
	        func(self)
	if "console" in self.exec_flags:
	  if "console" in self.mod.flags:
		self.c_display()  
      except AttributeError:
	pass	
    except :
	 error = sys.exc_info()
         self.error(error)
    self.setState()
    self.event.set()
    if not "thread" in self.exec_flags:
	self.result()

  def result(self):
    if self.res and len(self.res):
      self.lock.acquire()
      buff = self.vtreeprinter.fillMap(0, self.res)
      self.lock.release()
      print buff

  def error(self, trace = None):
     if trace:
	 err_type, err_value, err_traceback = trace
	 res = "\n\nWhat:\n"
         res +=  "----------\n"
         err_typeval = traceback.format_exception_only(err_type, err_value)
         for err in err_typeval:
           res += err
         res += "\nWhere:\n"
         res += "-----------\n"
	 err_trace =  traceback.format_tb(err_traceback)
         for err in err_trace:
           res += err
         self.lock.acquire()
         self.error_result += res 
         self.state = "Fail"
	 self.lock.release()

  def setState(self):
    self.lock.acquire()
    self.launchCount -= 1
    if self.launchCount <= 0:
        self.timeend = time.time()
        if self.state != "Fail":
          self.state = "Finish"
    self.lock.release()

  def __getattr__(self, attr):
     return  getattr(self.inst, attr)

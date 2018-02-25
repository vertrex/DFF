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

from Queue import Queue
import threading, time, datetime,sys, traceback 

from dff.api.vfs.libvfs import VFS, VLink
from dff.api.events.libevents import EventHandler
from dff.api.exceptions.libexceptions import envError, vfsError
from dff.api.types.libtypes import Variant, VMap, typeId, Argument, Parameter, ConfigManager
from dff.api.taskmanager.scheduler import sched
from dff.api.taskmanager.processus import ProcessusManager, Processus 
from dff.api.loader import loader 
from dff.api.types.libtypes import Config
from dff.api.filters.libfilters import Filter

class ModulesConfig():
  def __init__(self):
    self.modules = {}

  def __iter__(self):
     for mod in self.modules:
	yield mod

  def __len__(self):
     return len(self.modules)

  def __getitem__(self, mod):
     return self.modules[mod]

  def __str__(self):
     return str(self.modules)
 
  def modulesConfig(self):
     return self.modules
 
  def isSet(self, module):
     try :
        self.modules[module]
        return True
     except KeyError:
        return False

  def config(self, module):
     try:
	self.modules[module]
	return self.modules[module]
     except KeyError:
         return None

  def addArgument(self, module, argument, value):
     try:
       arguments = self.modules[module][0]
       if arguments == None:
	   arguments = {}
       arguments[argument] = value
       self.modules[module] = (arguments, self.modules[module][1])
       return True
     except KeyError, key:
       return False

  def argument(self, module, argument):
	try:
	  arguments = self.modules[module][0]
	  if arguments:
  	    return arguments[argument]
	  else:
	    return None
        except KeyError:
	  return None
	return None 

  def removeArgument(self, module, argument):
       try:
         arguments = self.modules[module][0]
	 if arguments:
	   arguments.pop(argument)
	   self.modules[module] = (arguments, self.modules[module][1])
	 else:
	   return False
	 return True
       except KeyError, key:
         return False

  def flag(self, module):
     try:
        return self.modules[module][1]
     except KeyError:
	return []
 
  def addFlag(self, module, flag):
      try:
         flags = self.modules[module][1]
	 if flag == None:
	   flag = []
	 flags.append(flag)
         self.modules[module] = (self.modules[module][0], flags)
         return True
      except KeyError, key:
         return False

  def removeFlag(self, module, flag):
       try:
	  flags = self.modules[module][1]
	  if flag in flags:
	    flags.remove(flag)
	    self.modules[module] = (self.modules[module][0], flags)
	  else:
	    return False
	  return True
       except KeyError, key:
	  return False

  def add(self, mod, args = None, exec_flags = []):
       try :
	 #if module already choosen overwrite argument or exec_flags only if none was set before
  	 (margs, mexec_flags) = self.modules[mod] 
         if margs:
	    args = margs
         if mexec_flags:
	    exec_flags = mexec_flags
	 self.modules[mod] = (args, exec_flags)
	 return False
       except KeyError:
	 self.modules[mod] = (args, exec_flags)	
	 return True

  def remove(self, mod, args = None, exec_flags = None):
       try :
	 self.modules.pop(mod)
	 return True 
       except KeyError:
	 return False

  def clear(self):
        self.modules.clear()

class TaskManager():
  class __TaskManager(EventHandler):
    def __init__(self):
      EventHandler.__init__(self)
      self.loader = loader.loader()
      self.processusManager = ProcessusManager()
      self.VFS = VFS.Get()
      self.VFS.connection(self)
      self.ppModules = ModulesConfig()
      self.ppAnalyses = ModulesConfig()

    def addPostProcessingModule(self, module):
       self.ppModules.add(module)

    def addPostProcessingModules(self, modules):
      for module in modules:
        self.ppModules.add(module)

    def addPostProcessingAnalyse(self, analyse):
       self.ppAnalyses.add(analyse)

    def addPostProcessingAnalyses(self, analyses): #analySIS XXX
      for analyse in analyses:
        self.ppAnalyses.add(analyse) 

    def join(self):
      ppsched.join()

    def addAnalyseDependencies(self):
       requiered = set() 
       for moduleName in self.ppAnalyses:
	  try:
            for module in self.loader.modules[moduleName].depends:
	      requiered.add(module)
	  except AttributeError:
	    pass
       for moduleName in requiered:
          try:
	     self.loader.modules[moduleName]
             self.ppModules.add(moduleName)
          except KeyError:
	    try:  
	      modules = self.loader.tags[moduleName]
	      for moduleName in modules:
		 self.ppModules.add(moduleName)
	    except KeyError:
		pass

    def moduleInstancesByName(self, name):
       instances = []
       for proc in self.processusManager:
          if proc.name == name:
            instances.append(proc)
       return instances   

    def processusByName(self, name):
       processus = []
       for proc in self.processusManager:
	 if proc.name == name:
           processus.append(proc)
       return processus

    def clearPostProcess(self):
        self.ppModules.clear()
	self.ppAnalyses.clear()

    def Event(self, e):
      if len(self.ppModules) and e != None and e.value != None:
        node = e.value.value()
        if node and not isinstance(node, VLink):
  	  ppsched.enqueueRegister(node)

    def postProcessWalk(self, node):
       job = (self.postProcess, (node,))
       ppsched.enqueueProcessing(job)	
       if node.hasChildren():
	 children = node.children()
	 for i in xrange(0, len(children)):
	     self.postProcessWalk(children[i])

    def postProcess(self, node, recursive = False):
      try:
       compatModule = node.compatibleModules()
       for mod in self.ppModules:
         moduleObj = self.loader.modules[mod]
         if (mod in compatModule) or ("generic" in moduleObj.flags):
	   (args, exec_flags) = self.ppModules[mod]
 	   nodeName = moduleObj.conf.argumentsByType(typeId.Node)[0].name()
           finalargs = {}
           if args != None:
             for key in args.iterkeys():
               finalargs[key] = args[key]
           if exec_flags == None:
             exec_flags = ["console", "thread"]
	   else:
             if not ("gui" in exec_flags or "console" in exec_flags):
	       exec_flags.append("console")
             if not "thread" in exec_flags:
	       exec_flags.append("thread")
           finalargs[nodeName] = node
           arg = moduleObj.conf.generate(finalargs)
	   if not self.processusManager.exist(moduleObj, arg):
             ppsched.enqueueProcessus((self.add, (mod, arg, exec_flags, True)))
      except:
        pass
        #print 'Post process error compat module : ', str(compatModule)
	#err_type, err_value, err_traceback = sys.exc_info()
        #for l in  traceback.format_exception_only(err_type, err_value):
	  #print l
        #for l in  traceback.format_tb(err_traceback):
	  #print l
 
    def postProcessAnalyse(self, root): 
       for mod in self.ppAnalyses:
          (args, exec_flags) =  self.ppAnalyses[mod] 
	  moduleObj = self.loader.modules[mod]
 	  nodeName = moduleObj.conf.argumentsByType(typeId.Node)
          if args == None:
           args = {}
          if exec_flags == None:
           exec_flags = ["gui", "thread"]
          else:
	    if not "thread" in exec_flags:
	      exec_flags.append("thread")
            if not ("gui" in exec_flags) and ("gui" in moduleObj.flags):
	      exec_flags.append("gui")
	  try :
	   if nodeName:
	      args[nodeName[0].name()] = root 
           arg = moduleObj.conf.generate(args)
	   ppsched.enqueueAnalyse((self.add, (mod, arg, exec_flags, True)))
	  except RuntimeError:
	    pass 

    def add(self, cmd, args, exec_flags, enqueued = False):
      mod = self.loader.modules[cmd] 
      proc = None
      if "single" in mod.flags:
         proc = self.processusManager.singleCreate(mod, None, exec_flags)
      else:
	proc = self.processusManager.create(mod, None, exec_flags)
      if not "thread" in exec_flags:
        try :
          if "gui" in proc.mod.flags and not "console" in proc.mod.flags:
            print "This script is gui only"
	    self.processusManager.remove(proc)
	    proc.event.set()
	    return proc
        except AttributeError:
	    pass
      if not isinstance(args, Config):
        try:
          args = mod.conf.generate(args)
        except:
          pass
      if enqueued:
	 proc.launch(args)
      else:
	 sched.enqueue(((proc.launch, args),) )
      return proc
  __instance = None

    
  def __init__(self):
    if TaskManager.__instance is None:
       TaskManager.__instance = TaskManager.__TaskManager()

  def __setattr__(self, attr, value):
	setattr(self.__instance, attr, value)

  def __getattr__(self, attr):
	return getattr(self.__instance, attr) 

  def add(self, cmd, args, exec_flags, endfunc = None):
       return self.__instance.add(cmd, args, exec_flags, endfunc)

class ScanQueue(Queue):
   def __init__(self):
      Queue.__init__(self)
      self.display = None
      self.count = 0
      self.countLock = threading.Lock()
      self.moduleMapCount  = {}
      self.loader = loader.loader()

   def registerDisplay(self, item, progress):
      self.displayItem = item
      self.displayProgress = progress
 
   def refresh(self):
      self.count = 0     
      self.moduleMapCount.clear()

   def task_done_scan(self, root, module):
     self.countLock.acquire()
     self.count += 1
     try:
       self.moduleMapCount[module] += 1
     except KeyError:
       self.moduleMapCount[module] = 1
     self.countLock.release()
     self.displayProgress(root, self.count, module, self.moduleMapCount[module])
     self.task_done()

   def scanJoin(self, root, modulesToApply = None):
      modMap = {}
      modCount = 0
      jobs = []
      while not self.empty():
         task = self.get()
         moduleName = task[1][0]
	 if modulesToApply != None:
	   if not module in modulesToApply:
	 	self.task_done()
		continue

         module = self.loader.modules[moduleName]
         try:
           filterText = module.scanFilter
           if filterText != '':
             arguments = task[1][1]
             nodeArguments = module.conf.argumentsByType(typeId.Node)
             if len(nodeArguments) == 1:
               node = arguments[nodeArguments[0].name()].value() 
               filter = Filter('')
               filter.compile(str(filterText))
               filter.process(node)
               matches = filter.matchedNodes()
               if not len(matches):
                 self.task_done()
                 continue
         except : #filter can throw 
           pass

         try :
  	   modMap[task[1][0]] += 1
	 except KeyError:
	   modMap[task[1][0]] = 1

	 job2 = (self.task_done_scan, (root, task[1][0],))
	 job = (task, job2)
         jobs.append(job)
	 modCount += 1
      if modCount:
        self.displayItem(root, modCount, modMap)
      for job in jobs:
        sched.enqueue(job)
      self.join()
      self.refresh()

class ProcessingQueue(ScanQueue):
   def __init__(self):
      ScanQueue.__init__(self)
      self.total = 0
      self.percent = 0

   def refresh(self):
      ScanQueue.refresh(self)
      self.total = 0
      self.percent = 0 	 
  
   def task_done_scan(self, root):
      self.countLock.acquire()
      self.count += 1
      newpercent = int(self.count * (100.00/self.total)) 
      if newpercent > self.percent:
	 self.percent = newpercent
	 newpercent = True
      else:
	 newpercent = False	
      self.countLock.release()
      if newpercent :
        self.displayProgress(root, self.count)
      self.task_done()

   def scanJoin(self, root):
      total = self.qsize()
      self.displayItem(root, total)
      self.total = total
      while not self.empty():
         task =  self.get()
         job2 = (self.task_done_scan, (root,))
         jobs = (task, job2)
         sched.enqueue(jobs)
      self.join() 
      self.refresh()

class PostProcessDisplay():
  def __init__(self, verbose = True):
     self.state = True 
     self.verbose = verbose
     self.init()

  def init(self):   
     self.processingRoot = {}
     self.processusRoot = {}
     self.processusModules = {}
     self.analyseRoot = {}
     self.analyseModules = {}

  def output(self, string):
     if self.verbose:
       print string

  def info(self, root):
     self.output(root.absolute())

  def updateState(self, state):
     self.state = state
     self.init()
     
  def ask(self, messageName, message):
     self.output(messageName + " " + message)

  def askWait(self, messageName, message):
     self.output(messageName + " " +  message)
     return True

  def processingItem(self, root, count):
     self.processingRoot[root] = count 

  def processingProgress(self, root, number):
     self.output(root.absolute() + " " + str(number) + " / " + str(self.processingRoot[root]))

  def processusItem(self, root, moduleCount, modMap):
     self.processusRoot[root] = moduleCount
     self.processusModules[root] = {}
     for modname, count in modMap.iteritems():
        self.processusModules[root][modname] = count

  def processusProgress(self, root, count, module, moduleCount):
     self.output(root.absolute() + " " + str(count) + " / " + str(self.processusRoot[root]))
     self.output(root.absolute() + ":" + module + " " + str(moduleCount) + " / " + str(self.processusModules[root][module]))

  def analyseItem(self, root, moduleCount, modMap):
     self.analyseRoot[root] = moduleCount
     self.analyseModules[root] = {}
     for modname, count in modMap.iteritems():
        self.analyseModules[root][modname] = count

  def analyseProgress(self, root, count, module, moduleCount):
     self.output(root.absolute() + " " + str(count) + " / " + str(self.analyseRoot[root]))
     self.output(root.absolute() + ":" + str(module) + " " + str(moduleCount) + " / " + str(self.analyseModules[root][module]))

class PostProcessScheduler():
     class __PostProcessScheduler():
        def __init__(self):
	  self.taskManager = TaskManager()
          self.registerQueue = Queue()
	  self.processingQueue = ProcessingQueue()
	  self.processusQueue = ScanQueue()
	  self.analyseQueue = ScanQueue()
	  self.display = PostProcessDisplay() 
	  self.displayState = self.display
          self.processingQueue.registerDisplay(self.display.processingItem, self.display.processingProgress)
          self.processusQueue.registerDisplay(self.display.processusItem, self.display.processusProgress)
          self.analyseQueue.registerDisplay(self.display.analyseItem, self.display.analyseProgress)
	  self.fullAuto = True
          self.finishedEvent = threading.Event()
          self.finishedEvent.clear()

        def join(self):
          self.finishedEvent.wait()

        def fullAutoMode(self, mode):
	   self.fullAuto = mode

	def getDisplay(self):
	   return self.display

        def displayRoot(self, root):
	   if self.display:
	     self.display.info(root)

        def registerState(self, func):
	   self.displayState = func

	def registerDisplay(self, func):
	   self.display = func

        def enqueueRegister(self, root):
	  if self.firstRoot and root.absolute().find(self.firstRoot.absolute()) != 0:
	    self.displayState.ask('Alert', 'Post processing is currently running ! To process ' + str(root.absolute()) + ' you can right-click it and choose scan, once current processing is finished.')
	  else:	
	    self.registerQueue.put(root)

	def enqueueProcessing(self, work):
	  self.processingQueue.put(work)

        def enqueueProcessus(self, work):
	   self.processusQueue.put(work)

	def enqueueAnalyse(self, work):
	   self.analyseQueue.put(work)

        def scanProcessus(self, root):
	   if root.fsobj(): #logical files don't have fsobj ...
             flags = self.taskManager.ppModules.flag(root.fsobj().name)
	   else:
	     flags = []
           if not 'noscan' in flags:
	     modulesToApply = None
	     if (not self.fullAuto) and self.display:
		if not self.displayState.askWait('Scanner', 'Do you want to scan ' + str(root.absolute())):
		  return
             self.displayState.updateState(True)
             self.displayRoot(root)
             self.taskManager.postProcessWalk(root)
             self.processingQueue.scanJoin(root)

	     if (not self.fullAuto) and self.display:
	       h = {}
	       for n in self.processusQueue.queue:
		  try:
		    h[n[1][0]] += 1
		  except KeyError:
		    h[n[1][0]] = 1
                
	       modulesToApply = self.displayState.askModulesWait('Apply module', 'Please select modules to apply', h)
             self.processusQueue.scanJoin(root, modulesToApply)

        def scanAnalyse(self, root, firstRoot):
	   if (not self.fullAuto) and self.display:
	     if not self.displayState.askWait('Scanner', 'Do you want to launch analyse on ' + str(firstRoot.absolute())):
	       return 
	   self.taskManager.postProcessAnalyse(firstRoot)
	   self.analyseQueue.scanJoin(root)

        def launch(self):
	  self.firstRoot = None
          self.finishedEvent.clear()
	  while True:
	       root = self.registerQueue.get()
	       if self.firstRoot == None:
	 	 self.firstRoot = root
	       self.scanProcessus(root)
	       if self.registerQueue.empty():
		 self.scanAnalyse(root, self.firstRoot)
		 self.displayState.updateState(False)
		 self.taskManager.clearPostProcess()
		 self.firstRoot = None	      
                 self.finishedEvent.set() 
     __instance = None
	
     def __init__(self):
	if PostProcessScheduler.__instance is None:
	   PostProcessScheduler.__instance = PostProcessScheduler.__PostProcessScheduler()
	
     def __setattr__(self, attr, value):
	setattr(self.__instance, attr, value)

     def __getattr__(self, attr):
	return getattr(self.__instance, attr)

ppsched = PostProcessScheduler()

thread = threading.Thread(target = ppsched.launch, name = "TaskManager")
thread.setDaemon(True)
thread.start()

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
#  Solal J. <sja@digital-forensic.org>
#

import threading, sys, traceback, multiprocessing 
from Queue import Queue 
from dff.api.types.libtypes import VMap

event_type = ["add_qwidget"]

class WorkQueue():
    class __WorkQueue():
        def launch(self):
          while True:
            work = self.waitQueue.get()
            self.workerQueue.put(work)

        def enqueue(self, proc):
          self.waitQueue.put(proc)

        def set_callback(self, type, func):
          if type in self.event_func:
            self.event_func[type].append(func)

        def worker(self):
           while True:
             queuedTask = self.workerQueue.get()
             for (func, arg) in queuedTask:
               try:
                 if func.im_class.__name__ == "Processus":
                   func(arg)
                 elif arg:
                   func(*arg)
                 else:	
                   func()
               except :
                 print "worker error"
                 err_type, err_value, err_traceback = sys.exc_info()
                 for n in  traceback.format_exception_only(err_type, err_value):
                   print n
                 for n in traceback.format_tb(err_traceback):
                   print n
             self.workerQueue.task_done() 

        def __init__(self, max = multiprocessing.cpu_count()): 
           self.waitQueue = Queue()
           self.workerQueue = Queue(max)
           self.pythonWorkerQueue = Queue(max)
           self.max = max
           self.event_func = {}
           for type in event_type:
             self.event_func[type] = []
           for i in range(max):
             thread = threading.Thread(target = self.worker, name = "Worker" + str(i))
             thread.setDaemon(True)
             thread.start()

    __instance = None
    def __init__(self):
      if WorkQueue.__instance is None:
        WorkQueue.__instance = WorkQueue.__WorkQueue()
    
    def __setattr__(self, attr, value):
      setattr(self.__instance, attr, value)

    def __getattr__(self, attr):
      return getattr(self.__instance, attr)

sched = WorkQueue()

def voidcall(node):
  pass

sched.set_callback("add_widget", voidcall)

thread = threading.Thread(target = sched.launch)
thread.setDaemon(True)
thread.start()

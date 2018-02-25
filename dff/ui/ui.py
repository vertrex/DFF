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

import sys, os, argparse
from distutils.sysconfig import get_python_lib

import dff
from dff.api.loader.loader import loader 
from dff.ui.conf import Conf
from dff.ui.redirect import RedirectIO
try:
    from dff.api.crashreporter.libcrashhandler import CrashHandler
    CrashHandlerEnabled = True
except ImportError:
    CrashHandlerEnabled = False
from dff import VERSION
from dff.api.taskmanager.taskmanager import TaskManager

# ensure dist-packages will be loaded be pyshared on Debian
# else private modules won't be found
if not os.path.exists(os.path.join("dff", "modules")) and os.path.exists(os.path.join(get_python_lib(), "dff")):
    sys.path.insert(0, os.path.join(get_python_lib()))

class UI():
  """This classes manage and let you launch different type of user 
interfaces"""
  def __init__(self, arguments):
   self.arguments = arguments
   if self.arguments:
       self.debug = self.arguments.debug
       self.verbosity = self.arguments.verbosity
   else:
       self.debug = False
       self.verbosity = 0
   RedirectIO(None, self.debug)
   # When UI is initialized from main, arguments are provided
   # When UI is initialized from shell widget, there are no arguments
   if CrashHandlerEnabled and self.arguments and not self.arguments.no_exception_handler:
       self.handler = CrashHandler()
       self.handler.setVersion(VERSION)
       if self.arguments.silent_report:
           self.handler.setSilentReport(True)
       self.handler.setHandler()
   self.loader = loader()

  def launch(self, modulesPaths = None):
     print 'This method must be overwritten by an inherited classes'

  def modulesLocalPath(self, modulesPaths):
     modulesLocalPath = []
     for modulesPath in modulesPaths:
        if os.name != "posix":
          modulesPath = modulesPath.replace('/', '\\')
        if os.path.exists(modulesPath):
          modulesLocalPath.append(modulesPath)
        else:
          modulesLocalPath.append(os.path.join(get_python_lib(), modulesPath)) 
     return modulesLocalPath

  def loadModules(self, modulesPaths, displayOutput = None, defaultConfig=None):
     modulesPaths = self.modulesLocalPath(modulesPaths)
     self.loader.do_load(modulesPaths, displayOutput, reload = False)
     if defaultConfig is not None:
         for module in defaultConfig:
             TaskManager().ppModules.add(module)
             flags = []
             arguments = {}
             if defaultConfig[module].has_key("flags"):
                 flags = defaultConfig[module]["flags"]
             if defaultConfig[module].has_key("arguments"):
                 arguments = defaultConfig[module]["arguments"]
             TaskManager().ppModules.add(module, arguments, flags)


def parseArguments():
    """Check command line argument"""
    parser = argparse.ArgumentParser(prog="DFF", description='Digital Forensics Framework')
    parser.add_argument("-v", "--version", action="version", version='%(prog)s ' + str(dff.VERSION))
    parser.add_argument("-g", "--graphical", dest="graphical", help="start the graphical interface", action="store_true")
    parser.add_argument("-l", "--language", dest="language", nargs='?', choices=["cn", "de", "en", "es", "fr", "it", "nl"], help="set the default language for user interface", default="fr")
    parser.add_argument("-b", "--batch", dest="batch", nargs='?', help="execute batch file containing either python code or dff commands (line starting with ! ) or both")
    parser.add_argument("-c", "--config", dest="configuration", nargs='?', help="use the provided file as configuration")
    parser.add_argument("-d", "--debug", dest="debug", help="redirect outputs (aka print) to console", action="store_true")
    parser.add_argument("--verbosity", dest="verbosity", nargs='?', help="change debug verbosity. If debug is not enabled there is no effect.", default=1, type=int)
    crash_report = parser.add_mutually_exclusive_group()
    crash_report.add_argument("--disable-exception-handler", dest="no_exception_handler", help="disable exception handler (useful while live debugging)", action="store_true")
    crash_report.add_argument("--silent-report", dest="silent_report", help="do not start the graphical report sender after crash and directly send the report (useful when running tests and wanting backtrace in case of crash)", action="store_true")
    arguments = parser.parse_args()
    return arguments


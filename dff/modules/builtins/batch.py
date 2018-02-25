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

__dff_module_postprocess_version__ = "1.0.0"
from code import InteractiveConsole

from dff.api.module.script import Script 
from dff.api.taskmanager.taskmanager import TaskManager
from dff.api.module.module import Module 
from dff.api.types.libtypes import Variant, Argument, typeId, ConfigManager

from dff.ui.console.completion import LineParser 

class InteractiveBatch(InteractiveConsole):
  def __init__(self, fname):
    self._locals = {}
    self._fname = fname
    InteractiveConsole.__init__(self, self._locals)
    self.lcount = 1
    self.err = False
    self.ifeed = False

  def write(self, data):
    self.err = True
    lidx = data.find("line")
    if lidx != -1:
      cidx = data.find(",", lidx)
      data = data[:lidx] + "line " + str(self.lcount) + data[cidx:]
    print data.rstrip()


  def lpush(self, line):
    if self.ifeed and line == line.lstrip():
      self.ifeed = self.push("")
      if self.err:
        raise RuntimeError
    self.ifeed = self.push(line.rstrip())
    if self.err:
      raise RuntimeError
    return self.ifeed


  def end(self):
    if not self.err:
      if self.ifeed:
        self.push("")
    if not self.err:
      _globals = globals()
      for key in self._locals:
        if not _globals.has_key(key):
          _globals[key] = self._locals[key]
      self.resetbuffer()


class BATCH(Script):
  def __init__(self):
    Script.__init__(self, "batch")
    self.tm = TaskManager()
    self.DEBUG = False
    self.VERBOSITY = 0
    self.lp = LineParser(self.DEBUG, self.VERBOSITY -1)
    self.cm = ConfigManager.Get()
 

  def start(self, args):
    path = args["path"].value().path
    print "executing batch script " + path 
    ib = InteractiveBatch(path)
    ifile = open(path) 
    ifeed = False
    err = None
    for line in ifile.xreadlines():
      lstrip = line.strip()
      if lstrip.startswith("!"):
        if ifeed:
          ifeed = ib.lpush("")
        cmds = self.lp.makeCommands(line[1:])
        for cmd in cmds:
          exec_type = ["console"]
          config = self.cm.configByName(cmd[0])
          args  = config.generate(cmd[1])
          proc = self.tm.add(cmd[0], args, exec_type)
          proc.event.wait()
      else:
        try:
          ifeed = ib.lpush(line)
        except RuntimeError:
          ifeed = False
          break
      ib.lcount += 1
    ib.end()
    ifile.close()
    return


class batch(Module):
  """Process a dff batch file"""
  def __init__(self):
    Module.__init__(self, "batch", BATCH)
    self.conf.addArgument({"name":"path",
			   "description": "Path to a dff batch file",
			   "input" : Argument.Required|Argument.Single|typeId.Path}) 	
    self.tags = "builtins"

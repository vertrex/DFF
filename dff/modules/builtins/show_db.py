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

__dff_module_show_db_version__ = "1.0.0"

from dff.api.module.script import Script
from dff.api.types.libtypes import Variant, Argument, typeId, ConfigManager
from dff.api.taskmanager.processus import ProcessusManager
from dff.api.module.module import Module 

from dff.ui.console.utils import VariantTreePrinter

class SHOW_DB(Script):
  def __init__(self):
     Script.__init__(self, "show_db")
     self.cm = ConfigManager.Get()
     self.processusManager = ProcessusManager()
     self.ti = typeId.Get()
     self.vtreeprinter = VariantTreePrinter()
     

  def processesByModuleName(self, modname):
    processes = []
    for proc in self.processusManager:
      if proc.name == modname:
        processes.append(proc)
    return processes


  def keyInConfigArguments(self, config, key):
    res = ""
    argument = config.argumentByName(key)
    if argument:
      if argument.type() == 0:
        res += "\n\targument switch"
      else:
        res += "\n\t\targument of type < " + self.ti.typeToName(argument.type()) + " >"
      count = argument.parametersCount()
      if count:
        res += "\n\t\tpredefined parameters: "
        parameters = argument.parameters()
        for parameter in parameters:
          if argument.type() == typeId.Node:
            res += str(parameter.value().absolute())
          else:
            res += str(parameter.toString())
        count -= 1
        if count:
          res += ", "
    return res


  def keyInConfigConstants(self, config, key):
    res = ""
    constant = config.constantByName(key)
    if constant:
      res += "\n\t\tconstant of type < " + self.ti.typeToName(constant.type()) + " >"
      items = constant.values()
      count = len(items)
      res += "\n\t\tdefined constants: "
      for item in items:
        if constant.type() == typeId.Node:
          res += str(item.value().absolute())
        else:
          res += str(item.toString())
        count -= 1
        if count:
          res += ", "
    return res


  def keyInProcessArguments(self, processes, key):
    res = ""
    for proc in processes:
      if proc.args.has_key(key):
        res += "\n\t\tparameters provided to process id " + str(proc.pid) + ":\n\t\t\t"
        arg = proc.args[key]
        if arg.type() == typeId.List:
          vlist = arg.value()
          lenvlist = len(vlist)
          for item in vlist:
            lenvlist -= 1
            if item.type() == typeId.Node:
              res += str(item.value().absolute())
            else:
              res += str(item.toString())
            if lenvlist:
              res += ", "
        elif arg.type() == typeId.Node:
          res += str(arg.value().absolute())
        else:
          res += str(arg.toString())
    return res


  def keyInVMap(self, vmap, key):
    res = ""
    for ikey in vmap.keys():
      vval = vmap[ikey]
      if vval.type() == typeId.Map:
        res += self.keyInVMap(vval.value(), key)
      elif vval.type() == typeId.List:
        res += self.keyInVList(vval.value(), key)
      elif ikey == key:
        if vval.type() == typeId.Node:
          res += "\n\t\t\t" + str(vval.value().absolute())
        elif vval.type() == typeId.List:
          res += self.vtreeprinter.fillList(3, vval.value())
        elif vval.type() == typeId.Map:
          res += self.vtreeprinter.fillMap(3, vval.value())
        else:
          res += "\n\t\t\t" + str(vval.toString())
        res += " (type < " + self.ti.typeToName(vval.type()) + " >)"
    return res
      

  def keyInVList(self, vlist, key):
    res = ""
    for item in vlist:
      if item.type() == typeId.Map:
        res += self.keyInVMap(item.value(), key)
      elif item.type() == typeId.List:
        res += self.keyInVList(item.value(), key)
    return res


  def keyInProcessResults(self, processes, key):
    res = ""
    for proc in processes:
      match = ""
      if len(proc.res):
        results = proc.res
        for ikey in results.keys():
          item = results[ikey]
          if ikey == key:
            if item.type() == typeId.Node:
              match += "\n\t\t\t" + str(item.value().absolute())
            elif item.type() == typeId.List:
              match += self.vtreeprinter.fillList(3, item.value())
            elif item.type() == typeId.Map:
              match += self.vtreeprinter.fillMap(3, item.value())
            else:
              match += "\n\t\t\t" + str(item.toString())
            match += " (type < " + self.ti.typeToName(item.type()) + " >)"
          elif item.type() == typeId.Map:
            match += self.keyInVMap(item.value(), key)
          elif item.type() == typeId.List:
            match += self.keyInVList(item.value(), key)
      if match:
        res += "\n\t\tresults of process id " + str(proc.pid) + ":"
        res += match
    return res
    

  def get_dbinfo(self, key):
      res = ""
      configs = self.cm.configs()
      for config in configs:
        if config.origin() != "show_db":
          processes = self.processesByModuleName(config.origin())
          match = self.keyInConfigArguments(config, key)
          if match:
            res += "\n\tmodule: " + config.origin()
            res += match
            res += self.keyInProcessArguments(processes, key)
          match = self.keyInConfigConstants(config, key)
          if match:
            res += "\n\tmodule: " + config.origin()
            res += match
          match = self.keyInProcessResults(processes, key)
          if match:
            res += "\n\tmodule: " + config.origin()
            res += match
      return res


  def fillProcessArgumentsKeys(self, keymap):
    for proc in self.processusManager:
      args = proc.args
      if args and proc.name != "show_db":
        for key in args.keys():
          if not keymap.has_key(key):
            keymap[key] = []
          arg = args[key]
          if arg.type() == 0:
            res = "\n\tswitch argument"
          else:
            res = "\n\targument of type " + self.ti.typeToName(arg.type())
          res += " from " + proc.mod.conf.origin() + " in processus " + str(proc.pid)
          if arg.type() == typeId.List:
            res += "\n\t\t"
            vlist = arg.value()
            lenvlist = len(vlist)
            for item in vlist:
              lenvlist -= 1
              if item.type() == typeId.Node:
                res += str(item.value().absolute())
              else:
                res += str(item.toString())
              if lenvlist:
                res += ", "
          elif arg.type() == typeId.Node:
            res += "\n\t\t"
            res += str(arg.value().absolute())
          elif arg.type() != 0:
            res += "\n\t\t"
            res += str(arg.toString())
        keymap[key].append(res)
    return keymap


  def fillKeyInList(self, vlist, keymap, cname, pid):
    for item in vlist:
      if item.type() == typeId.Map:
        keymap = self.fillKeyInMap(item.value(), keymap, cname, pid)
    return keymap


  def fillKeyInMap(self, vmap, keymap, cname, pid):
    for key in vmap.keys():
      if not keymap.has_key(key):
        keymap[key] = []
      val = vmap[key]
      if val.type() == typeId.List:
        res = "\n\tresult of type " + self.ti.typeToName(val.type())
        res += " from " + cname + " in processus " + str(pid)
        keymap[key].append(res)
        keymap = self.fillKeyInList(val.value(), keymap, cname, pid)
      elif val.type() == typeId.Map:
        res = "\n\tresult of type " + self.ti.typeToName(val.type())
        res += " from " + cname + " in processus " + str(pid)
        keymap[key].append(res)
        keymap = self.fillKeyInMap(val.value(), keymap, cname, pid)
      else:
        res = "\n\tresult of type " + self.ti.typeToName(val.type())
        res += " from " + cname + " in processus " + str(pid)
        if val.type() == typeId.Node:
          res += "\n\t\t" + str(val.value().absolute())
        else:
          res += "\n\t\t" + val.toString()
        keymap[key].append(res)
    return keymap


  def fillProcessResultsKeys(self, keymap):
    for proc in self.processusManager:
      results = proc.res
      if results and proc.name != "show_db":
        for key in results.keys():
          if not keymap.has_key(key):
            keymap[key] = []
          item = results[key]
          res = "\n\tresult of type " + self.ti.typeToName(item.type())
          res += " from " + proc.mod.conf.origin() + " in processus " + str(proc.pid)
          if item.type() == typeId.Node:
            res += "\n\t\t" + str(item.value().absolute())
            keymap[key].append(res)
          elif item.type() == typeId.List:
            keymap[key].append(res)
            keymap = self.fillKeyInList(item.value(), keymap, proc.mod.conf.origin(), proc.pid)
          elif item.type() == typeId.Map:
            keymap[key].append(res)
            keymap = self.fillKeyInMap(item.value(), keymap, proc.mod.conf.origin(), proc.pid)
          else:
            res += "\n\t\t" + str(item.value())
            keymap[key].append(res)
    return keymap


  def fillAllArgumentsKey(self, keymap):
    configs = self.cm.configs()
    for config in configs:
      if config.origin() != "show_db":
        arguments = config.arguments()
        for argument in arguments:
          argname = argument.name()
          if not keymap.has_key(argname):
            keymap[argname] = []
          if argument.type() == 0:
            stres = "\n\tswitch argument"
          else:
            stres = "\n\targument of type " + self.ti.typeToName(argument.type())
          stres += " from " + config.origin()
          pcount = argument.parametersCount()
          if pcount != 0:
            parameters = argument.parameters()
            stres += "\n\t\t"
            for parameter in parameters:
              if argument.type() == typeId.Node:
                stres += str(parameter.value().absolute())
              else:
                stres += parameter.toString()
              pcount -= 1
              if pcount != 0:
                stres += ", "
          keymap[argname].append(stres)
    return keymap


  def fillAllConstantsKey(self, keymap):
    configs = self.cm.configs()
    for config in configs:
      if config.origin() != "show_db":
        constants = config.constants()
        for constant in constants:
          cname = constant.name()
          if not keymap.has_key(cname):
            keymap[cname] = []
          stres = "\n\tconstant of type " + self.ti.typeToName(constant.type()) + " from " + config.origin()
          items = constant.values()
          pcount = len(items)
          stres += "\n\t\t"
          for item in items:
            if item.type() == typeId.Node:
              stres += str(item.value().absolute())
            else:
              stres += item.toString()
            pcount -= 1
            if pcount != 0:
              stres += ", "
          keymap[cname].append(stres)
    return keymap

  def get_alldbinfo(self):
    keymap = {}
    keymap = self.fillAllArgumentsKey(keymap)
    keymap = self.fillAllConstantsKey(keymap)
    keymap = self.fillProcessArgumentsKeys(keymap)
    keymap = self.fillProcessResultsKeys(keymap)
    res = ""
    for key in keymap.keys():
      res += "\n\n" + key
      for item in keymap[key]:
        res += item
    return res

  def start(self, args):
    res = "Variable DB\n"
    if args.has_key("key"):
      key = args['key'].value()
      res += "key <" + key + ">"
      match = self.get_dbinfo(key)
      if match:
        res += match
      else:
        res += " not found in db"
    else:
      res += self.get_alldbinfo()
    print res


class show_db(Module):
  """Show DFF Data-Base from a key-centric view"""
  def __init__(self):
    Module.__init__(self, "show_db", SHOW_DB)
    self.conf.addArgument({"name": "key",
                           "description": "Display only this key value",
                           "input": Argument.Single|Argument.Optional|typeId.String})
    self.tags = "builtins"

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

__dff_module_info_version__ = "1.0.0"

import time
from datetime import timedelta, datetime

from dff.api.module.script import Script 
from dff.api.loader import loader
from dff.api.module.module import Module
from dff.api.taskmanager.processus import ProcessusManager
from dff.api.types.libtypes import Parameter, Variant, Argument, typeId, ConfigManager

from dff.ui.console.utils import VariantTreePrinter

class INFO(Script, VariantTreePrinter):
  def __init__(self):
    Script.__init__(self, "info")
    VariantTreePrinter.__init__(self)
    self.loader = loader.loader()
    self.processusManager = ProcessusManager()
    self.cm = ConfigManager.Get()

  def show_config(self, modname):
    conf = self.cm.configByName(modname)
    res = "\n\tConfig:"
    arguments = conf.arguments()
    for argument in arguments:
      res += "\n\t\tname: " + str(argument.name())
      res += "\n\t\tdescription: " + str(argument.description()) 
      if argument.inputType() == Argument.Empty:
        res += "\n\t\tno input parameters"
      else:
        res += "\n\t\ttype: " + str(typeId.Get().typeToName(argument.type()))
        res += "\n\t\trequirement: "
        if argument.requirementType() == Argument.Optional:
          res += "optional"
        else:
          res += "mandatory"
        res += "\n\t\tinput parameters: "
        if argument.parametersType() == Parameter.NotEditable:
          res += "not editable "
        else:
          res += "editable "
        if argument.inputType() == Argument.List:
          res += "list"
        else:
          res += "single"
      pcount = argument.parametersCount()
      if pcount != 0:
        parameters = argument.parameters()
        res += "\n\t\tpredefined parameters: "
        for parameter in parameters:
          if argument.type() == typeId.Node:
            res += str(parameter.value().absolute())
          else:
            res += parameter.toString()
          pcount -= 1
          if pcount != 0:
            res += ", "
      res += "\n"
    constants = conf.constants()
    if len(constants) > 0:
      res += "\n\tConstant: \t"
      for constant in constants:
        res += "\n\t\tname: " + str(constant.name())
        res += "\n\t\tdescription: " + str(constant.description())
        res += "\n\t\ttype: " + str(typeId.Get().typeToName(constant.type()))
        cvalues = constant.values()
        cvallen = len(cvalues)
        if cvallen > 0:
          res += "\n\t\tvalues: "
          for cvalue in cvalues:
            if cvalue.type() == typeId.Node:
              res += str(cvalue.value().absolute())
            else:
              res += cvalue.toString()
            cvallen -= 1
            if cvallen != 0:
              res += ", "
        res += "\n"
    return res


  def show_arg(self, args):
    res = ""
    if len(args):
      res += "\n\n\t\tArguments: \t"
      for argname in args.keys():
        res += "\n\t\t\tname: " + argname
        res += "\n\t\t\tparameters: "
        val = args[argname]
        if val.type() == typeId.List:
          vlist = val.value()
          vlen = len(vlist)
          for item in vlist:
            if item.type == typeId.Node:
              res += str(val.value().absolute())
            else:
              res += item.toString()
            vlen -= 1
            if vlen != 0:
              res += ", "
        elif val.type() == typeId.Node:
          res += str(val.value().absolute())
    return res


  def show_res(self, results):
    res = self.fillMap(3, results, "\n\n\t\tResults:")
    return res

  def c_display(self):
     print self.info  

  def getmodinfo(self, modname):
    conf = self.cm.configByName(modname)
    if conf == None:
      return
    self.info +=  "\n" +  modname + self.show_config(modname)
    for proc in self.processusManager:
      if proc.mod.name == modname:
        self.info += "\n\tProcessus " + str(proc.pid)
        stime = datetime.fromtimestamp(proc.timestart)
        self.info += "\n\t\texecution started at : " + str(stime)
        if proc.timeend:
          etime = datetime.fromtimestamp(proc.timeend)
          self.info += "\n\t\texecution finished at : " + str(etime)
        else:
          etime = datetime.fromtimestamp(time.time())
        delta = etime - stime
        self.info += "\n\t\texecution time: " + str(delta)
        self.info += self.show_arg(proc.args)
        self.info += self.show_res(proc.res)
 
  def start(self, args):
    self.info = ""
    if args.has_key("modules"):
      modnames = args['modules'].value()
      for modname in modnames:
        self.getmodinfo(modname.value())
    else:
      self.modules = self.loader.modules
      for modname in self.modules:
        self.getmodinfo(modname)


class info(Module):
  """Show info on loaded drivers: configuration, arguments, results
  """
  def __init__(self):
    Module.__init__(self, "info", INFO)
    self.tags = "builtins"
    self.conf.addArgument({"name": "modules",
                           "description": "Display information concerning provided modules",
                           "input": Argument.Optional|Argument.List|typeId.String})

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

__dff_module_man_version__ = "1.0.0"

from dff.api.vfs import *
from dff.api.loader import *
from dff.api.module.module import *
from dff.api.module.script import *
from dff.api.loader.loader import loader
from dff.api.types.libtypes import Variant, Argument, typeId, Parameter, ConfigManager

class MAN(Script):
    def __init__(self):
        Script.__init__(self, "man")
        self.type = "man"
        self.loader = loader()
        self.cm = ConfigManager.Get()


    def show_config(self, modname):
        conf = self.cm.configByName(modname)
        lconf = self.loader.get_conf(modname)
        if conf == None:
            return "no module <" + modname + "> found"
        res = "\nhelp for module <" + modname + ">:\n"
        if lconf != None and len(lconf.description):
            res += "Description:\n\t" + lconf.description
        arguments = conf.arguments()
        for argument in arguments:
            res += "\nArgument: " + str(argument.name())
            res += "\n\tdescription: " + str(argument.description()) 
            if argument.inputType() == Argument.Empty:
                res += "\n\tno input parameters\n"
            else:
                res += "\n\ttype: " + str(typeId.Get().typeToName(argument.type()))
                res += "\n\trequirement: "
                if argument.requirementType() == Argument.Optional:
                    res += "optional"
                else:
                    res += "mandatory"
                res += "\n\tinput parameters: "
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
                    res += "\n\tpredefined parameters: "
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
            for constant in constants:
                res += "\nConstant: " + str(constant.name())
                res += "\n\tdescription: " + str(constant.description())
                res += "\n\ttype: " + str(typeId.Get().typeToName(constant.type()))
                cvalues = constant.values()
                cvallen = len(cvalues)
                if cvallen > 0:
                    res += "\n\tvalues: "
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

    def c_display(self):
        print self.info


    def start(self, args):        
        self.info = ""
        module = args["module"].value()
        self.info = self.show_config(module)


class man(Module):
    """Displays help on other module"""
    def __init__(self):
        Module.__init__(self, "man", MAN)
        self.conf.addArgument({"name": "module", 
                               "input": Argument.Single|Argument.Required|typeId.String,
                               "description": "module for which to print help"})
        self.tags = "builtins"

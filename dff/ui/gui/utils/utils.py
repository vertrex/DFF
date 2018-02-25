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
#  Francois Percot <percot@gmail.com>
# 
from types import StringType 

from PyQt4.QtGui import QMessageBox

from dff.api.vfs.libvfs import Node
from dff.api.loader import loader
from dff.api.taskmanager.taskmanager import TaskManager 
from dff.api.types.libtypes import typeId, ConfigManager, Argument, Parameter

class Utils():
    def __init__(self):
        pass

    @staticmethod
    def getSetTags():
	lmodules = loader.loader().modules
	setags = set()
	for mod in lmodules:
	  try:
	   setags.add(lmodules[mod].tags) 
	  except AttributeError:
	   pass
  	try :
	   setags.remove('')
	except KeyError:
	   pass
	return setags
	
    @staticmethod
    def formatSize(size):
        lsize = [" KB", " MB", " GB", "TB", "PB", "EB"]
        if size < 1024 :
            return str(size) + " bytes"
        
        for i in range(0, len(lsize)):
            tmp_size = size / 1024
            if (tmp_size < 1024):
                return str(tmp_size) + lsize[i]
            else:
                size = tmp_size
	return str(tmp_size) + lsize[i]
    @staticmethod
    def getPath(node):
        if not node :
            return ""
        if node.name() == "":
            return str("/")
        else :
            return str(node.absolute())

    @staticmethod
    def getValue(arg):
        if arg <> None:
            if arg.type == "int":
                return str(arg.get_int())
            elif arg.type == "string":
                return str(arg.get_string())
            elif arg.type == "node": 
                node = arg.get_node()
                return Utils.getPath(node)
            elif arg.type == "bool" :
                return str(arg.get_bool())
            elif arg.type == "path" :
                return str(arg.get_path().path)
        return "TYPE NOT DEFINE"
    
    @staticmethod
    def getArgsDriver(driver_name):
        l = loader.loader()
        return l.getdriver(driver_name).conf.descr_l
    
    @staticmethod
    def getArgs(modules_name):
        l = loader.loader()
        if type(modules_name) == StringType :
            return l.modules[modules_name].conf.arguments()
        else :
            return None
    
    @staticmethod
    def hasOneNodeArg(module, type):
        configs = ConfigManager.Get()
        mconf = configs.configByName(str(module))
        if len(mconf.arguments()) > 1:
            return None
        argsnode = mconf.argumentsByType(typeId.Node)
        required = mconf.argumentsByRequirementType(Argument.Required)
        if len(argsnode) == 0:
            return None
        if len(argsnode) == 1:
            return argsnode[0].name()
        return None
        
    @staticmethod
    def execModule(name, type, nameArg, listNode):
        tm = TaskManager()
        configs = ConfigManager.Get()
        mconf = configs.configByName(str(name))
        arg = mconf.argumentByName(nameArg)
        if isinstance(listNode, Node):
            args = mconf.generate({arg.name(): listNode})
            tm.add(str(name), args, ["thread", "gui"])
	else:
            if arg.inputType() == Argument.List:
                args = mconf.generate({arg.name(): listNode})
                tm.add(str(name), args, ["thread", "gui"])
            else:
                for i in listNode:
                    args = mconf.generate({arg.name(): i})
                    tm.add(str(name), args, ["thread", "gui"])
        

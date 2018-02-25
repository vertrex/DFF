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
import sys
import traceback

from dff.api.module.script import *
from dff.api.exceptions.libexceptions import *
from dff.api.vfs import *
from dff.api.types import libtypes
from dff.api.vfs.libvfs import *

class Module(object):
  def __init__(self, name, icl):
    self.cl = icl
    self.name = name
    self.single = None
    self.icon = None
    try :
     if issubclass(self.cl, Script):
       self.conf = libtypes.Config(name)
       self.conf.thisown = False
       if self.__doc__:
	   self.conf.description = self.__doc__
       self.getflags()
    except TypeError:
	pass
    try :
      if issubclass(self.cl, mfso) or issubclass(self.cl, fso):
        self.conf = libtypes.Config(name)
        self.conf.thisown = False
        if self.__doc__:
	   self.conf.description = self.__doc__
        self.getflags()
    except TypeError:
      pass      
    try :
      if self.tags == "":
	self.tags = "others"
    except AttributeError:
	self.tags = "others"
	    
 
  def getflags(self):
    try :
      if self.flags:
        pass
    except AttributeError:
       self.flags = [""] 
    try :
      if self.cl.c_display :
        self.flags += ["console"]
    except AttributeError: 
       pass
    try : 
      if self.cl.g_display: 
        self.flags += ["gui"]
    except AttributeError:
	pass

  def create(self):
    if "single" in self.flags:
	if self.single == None:
	   self.single = self.cl()
        return self.single
    try :
     if issubclass(self.cl, Script):
       return self.cl()
    except TypeError:
	pass
    try :
      if issubclass(self.cl, mfso) or issubclass(self.cl, fso):
        try :
          fs = self.cl()
          return fs
        except : 
  	  exc_type, exc_value, exc_traceback = sys.exc_info()
	  traceback.print_exception(exc_type, exc_value, exc_traceback, None, sys.stdout)
    except TypeError: 
      pass


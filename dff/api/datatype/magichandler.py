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
import os, sys

if hasattr(sys, "frozen"):
   from dff.api.magic import magic
else:
#    try:
#       import magic
#    except:
   from dff.api.magic import magic

from dff.api.exceptions.libexceptions import vfsError 
from dff.api.types.libtypes import Variant
from dff.api.datatype.libdatatype import DataTypeHandler, DataTypeManager

class Magic(DataTypeHandler):
  def __init__(self):
     DataTypeHandler.__init__(self)
     self.__disown__()
     self.mgc_path = None
     if hasattr(sys, "frozen"):
        self.mgc_path = os.path.abspath(os.path.join(os.path.dirname(sys.executable), "resources/magic.mgc"))
     else:
        mgcpath = os.path.realpath(__file__)
        idx = mgcpath.rfind("api")
        if idx != -1:
           mgcpath = mgcpath[:idx+3]
        self.mgc_path = os.path.join(mgcpath, "magic", "magic.mgc")


  def typeFromBuffer(self, buff):
     if not len(buff):
        return "empty"
     mime = None
     buffmime = "unknown"
     f = None
     try:
        mime = magic.open(magic.MAGIC_NONE)
        mime.load(self.mgc_path)
        buffmime = mime.buffer(buff)
     except Exception as e:
        print e
        #print "Magic error can't read buffer on node : ",  node.absolute(), "\n", e
        buffmime = "error"
     finally:
        if mime is not None:
           mime.close()	
     return buffmime
     

  def type(self, node):
    if node.size() > 0:
       mime = None
       filemime = "unknown"
       f = None
       try:
          mime = magic.open(magic.MAGIC_NONE)
          mime.load(self.mgc_path)
          f = node.open()
          #cannot read less than 0x2000 because of vshadow signature starting @0x1e00
          buff = f.read(0x2000)
          filemime = mime.buffer(buff)
       except Exception as e:
          #print "Magic error can't read buffer on node : ",  node.absolute(), "\n", e
          filemime = "error"
       finally:
          if f is not None:
            f.close()
          if mime is not None:
             mime.close()	
       return filemime
    elif node.hasChildren() or node.isDir():
       return "directory"
    else:
       return "empty"

magicHandler = Magic()

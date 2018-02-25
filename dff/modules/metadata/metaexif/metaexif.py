# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
# 
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
#  Christophe Malinge <cma@digital-forensic.org>

__dff_module_metaexif_version__ = "1.0.0"

from time import strptime
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.module.manager import ModuleProcessusHandler
from dff.api.types.libtypes import Variant, VMap, VList, Argument, typeId, DateTime 
from dff.api.vfs.libvfs import AttributesHandler, VFS

import datetime, sys, traceback
def error():
   err_type, err_value, err_traceback = sys.exc_info()
   for n in  traceback.format_exception_only(err_type, err_value):
     print n
   for n in traceback.format_tb(err_traceback):
     print n



class EXIFHandler(AttributesHandler, ModuleProcessusHandler):
  dateTimeTags = [0x0132, 0x9003, 0x9004]
  def __init__(self):
    AttributesHandler.__init__(self, "exif")
    ModuleProcessusHandler.__init__(self, "metaexif")
    self.exifnodes = []
    self.vfs = VFS.Get()
    self.__disown__()
 
  def update(self, processus):
     pass
 
  def nodes(self, root):
     lnodes = []
     rootAbsolute = root.absolute()
     for node in self.exifnodes:
        node = self.vfs.getNodeById(node)
	if node.absolute().find(rootAbsolute) == 0:
	  lnodes.append(node)
     return lnodes

  def setAttributes(self, node):
     self.exifnodes.append(node.uid()) 

  def haveExif(self, node):
    vfile = node.open()
    img = Image.open(vfile) 
    info = img._getexif()
    vfile.close()
    if info == None:
	return False
    if len(info):
      return True
    return False

  def toDegree(self, value):
    d0 = value[0][0]
    d1 = value[0][1]
    d = float(d0) / float(d1)
    m0 = value[1][0]
    m1 = value[1][1]
    m = float(m0) / float(m1)
    s0 = value[2][0]
    s1 = value[2][1]
    s = float(s0) / float(s1)
    return d + (m / 60.0) + (s / 3600.0)

  def attributes(self, node):
    attr = VMap()
    vfile = node.open()
    img = Image.open(vfile) 
    info = img._getexif()
    vfile.close()
    for tag, values in info.items():
      if tag in self.dateTimeTags:
       try:
	decoded = str(TAGS.get(tag, tag))
 	try:
	  dt = strptime(values, "%Y:%m:%d %H:%M:%S") 
        except ValueError:
	  try:
	    dt = strptime(values[:-6], "%Y-%m-%dT%H:%M:%S")
	  except ValueError:
	    dt = strptime(values.rstrip(' '),  "%a %b %d %H:%M:%S")
	vt = DateTime(dt.tm_year, dt.tm_mon, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec)
        vt.thisown = False
	attr[decoded] = Variant(vt) 	
       except Exception as e:
	attr[decoded] = Variant(str(values))
      else:	
        decoded = str(TAGS.get(tag, tag))
        if decoded == "GPSInfo":
          try:
            gpsMap = VMap()
            for subvalue in values:
              subDecoded = GPSTAGS.get(subvalue, subvalue)
              v = values[subvalue]
              if str(subDecoded) == "GPSLatitude":
                degree = self.toDegree(v)
                try:
                  ref = gpsMap["GPSLatitudeRef"]
                except:
                  ref = ""
                if str(ref) != "N":
                  degree = 0 - degree
                gpsMap["GPSLatitudeRef"] = Variant(str(degree))
              elif str(subDecoded) == "GPSLongitude":
                 degree = self.toDegree(v)
                 try:
                   ref = gpsMap["GPSLongitudeRef"]
                 except:
                   ref = ""
                 if str(ref) != "E":
                   degree = 0 - degree
                 gpsMap["GPSLongitudeRef"] = Variant(str(degree)) #Variant don't handle float..
              elif type(v) == str:
                gpsMap[str(subDecoded)] = Variant(str(v))
              elif type(v) == unicode:
                gpsMap[str(subDecoded)] = Variant(str(v.encode('ascii', 'replace')))
              elif type(v) == tuple:
                vl = VList()
                for vv in v:
                  if type(vv) == tuple:
                    vl.push_back(Variant(str(vv)))
                gpsMap[str(subDecoded)]  = vl
              #XXX handle gps datetime  
              else:
                gpsMap[str(subDecoded)] = Variant(str(v))
            attr[decoded] = gpsMap
          except Exception as e:
            pass
            #print "Metaexif error encoding: ", e
        elif isinstance(values, tuple):
	  vl = VList()
	  for value in values:
             if type(values) == unicode:
	       vl.push_back(Variant(value.encode('ascii', 'replace')))
             elif type(values) == tuple:
               vl.push_back(Variant(str(value)))
             else:
	       vl.push_back(Variant(value))
          attr[decoded] = vl
        else:
          if type(values) == unicode:
            attr[decoded] = Variant(values.encode('ascii', 'replace'))
          elif type(values) == tuple:
            attr[decoded] = Variant(str(values))
          else:
            attr[decoded] = Variant(values)
    return attr

class MetaEXIF(Script):
  def __init__(self):
   Script.__init__(self, "metaexif")
   self.handler = EXIFHandler() 

  def start(self, args):
    try:
      node = args['file'].value()
      attr = self.handler.haveExif(node)
      if attr == True:
        self.stateinfo = "Registering node: " + str(node.name())
        self.handler.setAttributes(node)
        node.registerAttributes(self.handler)
    except Exception as e:
      print "Metaexif error on node ", str(node.absolute()) , " :"
      print str(e)
      pass

class metaexif(Module): 
  """This module parses and sets as node's attributes exif metadata"""
  def __init__(self):
    Module.__init__(self, "metaexif", MetaEXIF)
    self.conf.addArgument({"name": "file",
                           "description": "Parses metadata of this file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["image/jpeg", "image/tiff"]})
    self.flags = ["single"]
    self.tags = "Metadata"

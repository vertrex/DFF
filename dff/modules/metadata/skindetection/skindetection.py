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
#  Solal Jacob <sja@digital-forensic.org>


__dff_module_skindetection_version__ = "1.0.0"

from PIL import Image

from dff.api.vfs.libvfs import TagsManager, AttributesHandler
from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.types.libtypes import Argument, typeId, Variant, VMap, Parameter

class SkinDetectionHandler(AttributesHandler):
  def __init__(self):
    AttributesHandler.__init__(self, "skindetection")
    self.skinnodes = {}
    self.__disown__()

  def attributes(self, node):
     attr = VMap() 
     try: 
       attr["skin percent"] = Variant(self.skinnodes[node.uid()])
     except Exception :
       pass
     return attr

class SkinDetection(Script):
  #from http://www.naun.org/multimedia/NAUN/computers/20-462.pdf
  def __init__(self):
   Script.__init__(self, "skindetection")
   self.handler = SkinDetectionHandler()
   self.threshold = 0.3  #node will be tagged if > threshold
   self.thumbnailSize = 128 #smaller is faster but less prcesise
   self.tagNode = False 

  def detectSkin(self, node):
    vfile = node.open()
    img = Image.open(vfile)
    if not img.mode == 'YCbCr':
        img = img.convert('YCbCr')
    img.thumbnail((self.thumbnailSize, self.thumbnailSize), Image.ANTIALIAS)
    ycbcr_data = img.getdata() 
    imageWidth, imageHeight = img.size
    vfile.close()
    count = 0
    #try with hsv too
    for i,ycbcr in enumerate(ycbcr_data):
        y,cb,cr = ycbcr
        #if 86 <= cb <= 127 and 130 <= cr < 168:
        if 80 <= cb <= 120 and 133 <= cr <= 173:
            count += 1
    self.handler.skinnodes[node.uid()] =  int((float(count) / (imageWidth*imageHeight))*100)
    node.registerAttributes(self.handler)
    if self.tagNode:
      if count > self.threshold*imageWidth*imageHeight: 
        node.setTag("explicit")

  def start(self, args):
    try:
      node = args['file'].value()
      try:
        self.threshold = args['threshold'].value() / float(100)
      except Exception:
        pass
      try:
        if args['tag'].value():
          self.tagNode = True 
      except Exception:
        pass
      self.detectSkin(node)
    except Exception as e:
      pass
      #print "Skin detection error on node ", str(node.absolute()) , " :"
      #print str(e)

class skindetection(Module): 
  """This module try to detect skin in pictures and set a percent of skin in attribute, it can also tags picture with the 'explicit' if percent of skin superior than a specified value.
The result is not accurate and have a certain percent of false positive."""
  def __init__(self):
    Module.__init__(self, "skindetection", SkinDetection)
    self.conf.addArgument({"name": "file",
                           "description": "Parses metadata of this file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["image"]})
    self.conf.addArgument({"name" : "tag",
                           "input" : Argument.Empty,
                           "description" : "Node will be tagged as 'explicit' if this argument is set"})
    self.conf.addArgument({"name": "threshold",
                           "description" : "Node will be tagged 'explicit' if percent of skin is superior than this value (default is 30 percent)",
                           "input" : Argument.Optional|Argument.Single|typeId.UInt64,
                           "parameters" : { "type" : Parameter.Editable, "predefined" : [30] } })
    self.flags = ["single"]
    self.tags = "Metadata"
    self.icon = ":meeting"
    tagsManager = TagsManager.get()
    tagsManager.add('explicit', 255, 85, 127)

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

import datetime, sys, traceback
from dff.api.vfs.libvfs import VFS, Node
from dff.api.types.libtypes import VMap, Variant

from olevba import _extract_vba, decompress_stream, VBA_Scanner 

class FakeOle(object):
  def __init__(self, node):
     self.basePathNode = node 

  def openstream(self, name):
     #must be faster than a get node on all the vfs
     name = name.encode('UTF-8')
     if name.rfind('/'):
       name = name[name.rfind('/') + 1:]
     if name == "PROJECT": 
       children = self.basePathNode.parent().children()
     else:
       children = self.basePathNode.children()
     for child in children:
       if name == child.name():
         node = child
         break
     vfile = node.open()
     return vfile 

class VBANode(Node):
  def __init__(self, name, size, parent, fsobj, attributes):
     Node.__init__(self, name, size, parent, fsobj)
     self.__disown__()
     self.attr  = VMap()
     self.attr["VBA"] = attributes
     self.setTag("suspicious")

  def _attributes(self):
    return self.attr

class VBA(object):
  def __init__(self, parent, mfsobj, stream, args):
   decompressVBA = not 'no-vba-decompression' in args
   addRootMetadata = not 'no-root_metadata' in args
   try:
     hasSuspiscious = None
     children = stream.children()
     for childStream in children:
       if childStream.name() == "dir":
         dir_path = childStream
         break
     vba_root = stream.parent()
     project_path = None
     children = vba_root.children()
     for childStream in children:
        if childStream.name() == "PROJECT":
          project_path = childStream
          break
     result = _extract_vba(FakeOle(stream), vba_root.name() + "/", project_path.name(), dir_path.name())
     for streamPath, fileName, vbaDecompressed, compressedOffset in result:
       hasSuspiscious = False 
       scanner = VBA_Scanner(vbaDecompressed)
       scanner.scan()
       name = streamPath[streamPath.rfind('/') + 1:].encode('UTF-8')
       children = stream.children()
       for child in  children: 
          if child.name() == name:
            vbaStream = child
            break
       attributesMap = VMap() 
       for (detectionType, keyword, desc,)  in  scanner.results:
         hasSuspiscious = True 
         attributesMap[str(detectionType)] = Variant(str(keyword))
       if addRootMetadata:
         parent.extraAttr.append(("VBA", vbaStream.name(), attributesMap, ))
       if decompressVBA:
         uncompressedSize = vbaStream.size() - compressedOffset
         if uncompressedSize > 0:
           vbanode = VBANode(str(name) + ".vba", vbaStream.size() - compressedOffset, vbaStream, mfsobj, attributesMap)
           mfsobj.setVBACompressed(vbanode, compressedOffset)
       else:
         for childStream in parent.cdh.streams():
            if childStream.this == vbaStream.this:
              childStream.setExtraAttributes(("VBA", attributesMap))
              childStream.setTag("suspicious")
     if hasSuspiscious:
      parent.node.setTag("suspicious")
   except Exception as e:
     err_type, err_value, err_traceback = sys.exc_info()
     for n in  traceback.format_exception_only(err_type, err_value):
       print n
     for n in traceback.format_tb(err_traceback):
       print n
     print "VBA analyzer on node ", parent.node.absolute(),  " error :"
     print  e 
     pass

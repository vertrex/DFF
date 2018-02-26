# DFF -- An Open Source Digital Forensics Framework
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
#  Romain BERTHOLON < rbe@digital-forensic.fr>
#

from array import array
from xml.etree.ElementTree import dump

from dff.modules.evtx.evtx_header import *
from dff.modules.evtx.xml_node import *

class EvtxInfo():
  def __init__(self, offset, event, count, node_ptr):
    #event, chunk.events()[event], count,
    self.__offset = offset
    self.__event = event
    self.__count = count
    self.__node = node_ptr

  def offset(self):
    return self.__offset

  def event(self):
    return self.__event

  def count(self):
    return self.__count

  def node(self):
    return self.__node

  def __hash__(self):
     return 1

  def __eq__(self, other):
     if (self.__node == other.node()) and (self.__offset == other.offset()):
       return True
     return False

  def __str__(self):
     return str(self.__node) + str(self.__offset)
  

class Record():
    def __init__(self, vfile, offset_rec, total_size):
        self._offset_rec = offset_rec
        self.sub_arrays = []
        self.__buff = vfile
        self.__record = EvtxRecord(vfile, offset_rec)

        self.id = 0
        self.source = ""
        self.date = ""
        self.lvl = -1

        self.root = None
        self.nodes = [] 
        if self.__record.Magic != "**\0\0":
            print "The record signature does not match '**'"
        else:
            self.parse(total_size)
        self.len = self.__record.Length1

        # used for debyug
#        if self.root is not None:
#            dump(self.root)

    def parse(self, total_size):
        root_node = RootNode(self.__buff,\
                             self.__record.offset + self.__record.templateSize(),\
                             total_size, self)
        offset = root_node.parse(self.__record.offset + self.__record.templateSize())
        return offset

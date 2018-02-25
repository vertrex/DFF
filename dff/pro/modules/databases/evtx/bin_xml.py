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

from array import array

from dff.modules.evtx.evtx_header import *
from dff.modules.evtx.xml_node import *

class BinXml:
    def __init__(self, buff, record, total_size):
        self.__buff = buff
        self.__record = record
        self.__template_size = 0
        self.__sub_array_offset = 0
        self.__offset_xml = 0
        offset = self.parse(self.__record.offset, total_size)

    def parse(self, real_offset, total_size):
#        print "Offset record :", self.__record.offset
        root_node = RootNode(self.__buff,\
                             self.__record.offset + self.__record.templateSize(),\
                             total_size)
        if not root_node.isValid():
            print "Invalid Root Node. Skipping event."
            return
        offset = root_node.parse(self.__record.offset + self.__record.templateSize())

#        print "Offset sub ARRAY == ", offset
        return offset

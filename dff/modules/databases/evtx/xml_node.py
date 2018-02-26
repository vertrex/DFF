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

import struct
import binascii
from array import array
from xml.etree.ElementTree import Element, SubElement

from dff.modules.evtx.evtx_header import SubstitutionEntry
from dff.modules.evtx.dtime import DTime
from dff.modules.evtx.xml_headers import *

class SubArray():
    def __init__(self, vfile, offset, parent):
        self.__offset = offset
        self.__count = 0
        self.__buff = vfile
        self._entry = []
        self._offsets = []
        self._values = []
        self.parent = parent

        # this enum is defined here : http://msdn.microsoft.com/EN-US/library/aa385616.aspx
        self.convertTo = {
            0x00:self.EvtVarTypeNull, #suppresses optional substitution
            0x01:self.EvtVarTypeString, #UCS2-LE
            0x81:self.EvtVarTypeString, #UCS2-LE LOLILOL
            0x02:self.EvtVarTypeAnsiString,
            0x03:self.EvtVarTypeSByte, #signed 8bit integer
            0x04:self.EvtVarTypeByte, #unsigned 8bit integer
            0x05:self.EvtVarTypeInt16, #signed 16bit integer
            0x06:self.EvtVarTypeUInt16, #unsigned 16bit integer
            0x07:self.EvtVarTypeInt32, #signed 32bit integer
            0x08:self.EvtVarTypeUInt32, #unsigned 32bit integer
            0x09:self.EvtVarTypeInt64, #signed 64bit integer
            0x0a:self.EvtVarTypeUInt64, #unsigned 64bit integer
            0x0b:self.EvtVarTypeSingle, #single precision floating point number
            0x0c:self.EvtVarTypeDouble, #double precision floating point number
            0x0d:self.EvtVarTypeBoolean, #true/false, occupies 4 bytes
            0x0e:self.EvtVarTypeBinary, #stream of binary data
            0x0f:self.EvtVarTypeGuid, #global unique identifier, 16 bytes
            0x10:self.EvtVarTypeSizeT, #size_t, either 32 or 64bit wide
            0x11:self.EvtVarTypeFileTime, #64 bit, 100ns since 1601-01-01 00:00:00
            0x12:self.EvtVarTypeSysTime, #32bit, seconds since 1970-01-01 00:00:00
            0x13:self.EvtVarTypeSid, #security identifier (variable length)
            0x14:self.EvtVarTypeHexInt32, #32bit integer in hex notation
            0x15:self.EvtVarTypeHexInt64, #64bit integer in hex notation
            0x20:self.EvtVarTypeEvtHandle, #event log object
            0x21:self.EvtVarTypeEvtBXml, #undocumented binary XML for an event
            0x23:self.EvtVarTypeEvtXml #XML for an event
            }

    def getDataCount(self):
        tmp = array('B', self.__buff[self.__offset:4 + self.__offset])
        self.__count = struct.unpack('<I', tmp)[0]
        return self.__count

    def getValues(self):
        tab_size = self.__count * 4 + 4
        size = 0
        for i in range(self.__count):
            entry = SubstitutionEntry(self.__buff, self.__offset + 4 * (i + 1))
            self._entry.append(entry)
            tmp = bytearray(self.__buff[self.__offset + tab_size + size:self.__offset + tab_size + size+ entry.size])
            self._offsets.append(self.__offset + tab_size + size)            
            size += entry.size
            self._values.append(tmp)

    def substitute(self, index):
        try:
            val_type = self._entry[index].type
            value = self._values[index]
            return self.convertTo[val_type](value, index)
        except KeyError:
            print "Cannot substitute index ", index
            return None

    def EvtVarTypeNull(self, value, index): #suppresses optional substitution
        return ""
            
    def EvtVarTypeString(self, value, index): #UCS2-LE
        value_list = unicode(value.decode('utf-16', 'replace')).split("\x00")
        string = unicode()
        for i in value_list:
            string += i.strip("\x19")
        return string

    def EvtVarTypeAnsiString(self, value, index):
        return str(value).rstrip("\0")

    def EvtVarTypeSByte(self, value, index): #signed 8bit integer
        val = struct.unpack('<b', str(value))
        return str(val[0])

    def EvtVarTypeByte(self, value, index): #unsigned 8bit integer
        val = struct.unpack('<B', str(value))
        return str(val[0])

    def EvtVarTypeInt16(self, value, index): #signed 16bit integer
        val = struct.unpack('<h', str(value))
        return str(val[0])

    def EvtVarTypeUInt16(self, value, index): #unsigned 16bit integer
        val = struct.unpack('<H', str(value))
        return str(val[0])

    def EvtVarTypeInt32(self, value, index): #signed 32bit integer
        val = struct.unpack('<i', str(value))
        return str(val[0])

    def EvtVarTypeUInt32(self, value, index): #unsigned 32bit integer
        val = struct.unpack('<I', str(value))
        return str(val[0])

    def EvtVarTypeInt64(self, value, index): #signed 64bit integer
        val = struct.unpack('<q', str(value))
        return str(val[0])

    def EvtVarTypeUInt64(self, value, index): #unsigned 64bit integer
        val = struct.unpack('<Q', str(value))
        return str(val[0])

    def EvtVarTypeSingle(self, value, index): #single precision floating point number
        val = struct.unpack('<f', str(value))
        return str(val[0])

    def EvtVarTypeDouble(self, value, index): #double precision floating point number
        val = struct.unpack('<d', str(value))
        return str(val[0])

    def EvtVarTypeBoolean(self, value, index): #true/false, occupies 4 bytes
        val = struct.unpack('<i', str(value))
        if val[0]:
            return "True"
        return "False"

    def EvtVarTypeBinary(self, value, index): #stream of binary data
        string = ""
        for c in value:
            string += hex(c)[2:]
        for c in value:
            try:
                if int(binascii.b2a_qp(str(c))) >= 32:
                    string += chr(int(binascii.b2a_qp(str(c)))).encode('ascii')
                else:
                    string += "."
            except:
                string += "."
        return string

    def EvtVarTypeGuid(self, value, index): #global unique identifier, 16 bytes
        val = struct.unpack("<BBBBBBBBBBBBBBBB", str(value))
        return str(val[0])

    def EvtVarTypeSizeT(self, value, index): #size_t, either 32 or 64bit wide
        return str(value)

    def EvtVarTypeFileTime(self, value, index): #64 bit, 100ns since 1601-01-01 00:00:00
        val = struct.unpack('<Q', str(value))
        time = DTime(val[0])
        return time.toNT64()

    def EvtVarTypeSysTime(self, value, index): #32bit, seconds since 1970-01-01 00:00:00
        val = struct.unpack('<I', str(value))
        time = DTime(val[0])
        return time.toPosix()

    def EvtVarTypeSid(self, value, index): #security identifier (variable length)
        sid = UserSID(str(value), 0)
        count = sid.SubAuthorityCount

        string = "S" + str(sid.revision) + "-"

        t = bytearray(sid.IdentifierAuthority)
        for i in t:
            if i:
                string += hex(i)
        offset = 8
        for i in range(count):
            val = struct.unpack(">I", ''.join([chr(x) for x in value[offset:offset+4]]))
            offset += 4
            string += ("-" + hex(val[0]))
        return string

    def EvtVarTypeHexInt32(self, value, index): #32bit integer in hex notation
        val = struct.unpack('<I', str(value))
        return hex(val[0])

    def EvtVarTypeHexInt64(self, value, index): #64bit integer in hex notation
        val = struct.unpack('<Q', str(value))
        return hex(val[0])

    def EvtVarTypeEvtHandle(self, value, index): #event log object
        return "Not handled yet 4"

    def EvtVarTypeEvtBXml(self, value, index): #undocumented binary XML for an event
        opcode =  struct.unpack('<B', self.__buff[self._offsets[index]])
        if opcode[0] & 0x0f == 0x0f:
            xml = RootNode(self.__buff, self._offsets[index], len(value), self.parent)
            xml.parse(self._offsets[index])
        elif opcode[0] & 0x0f == 0x0c:
            xml = TemplateNode(self.__buff, self._offsets[index], len(value), self.parent)
            xml.parse(self._offsets[index])
        return ""

    def EvtVarTypeEvtXml(self, value): #XML for an event
        return str(value)

class XmlNode():
    def __init__(self, buff, offset, size, opcode, total_size):
        self._size = size
        self._buff = buff
        self._offset_begin = offset
        self._opcode = opcode
        self._total_size = total_size

    def isValid(self):
        pass

    def getOpcode(self):
        """
        Get the opcode. This is the default implementation unpacking only the 1st
        byte of the bin stream. This should be reimp by sub-classes to get xml
        properly.
        """
        opcode = unpack_from('B', self._buff, self._offset_begin)[0]
        if (opcode & 0x0f) != self._opcode:
            print "KO"
        return opcode

    def child(self, opcode):
        node = node_types[opcode]

class RootNode(XmlNode):
    def __init__(self, buff, offset, total_size, parent = None):
        XmlNode.__init__(self, buff, offset, 4, 0x0f, total_size)

        self.parent = parent

        self.__header = XMLNode0x00(buff, offset)
        self.getOpcode()

    def getOpcode(self):
        if (self.__header.opcode & 0x0f) != self._opcode:
            print "ERROR expected 0x0f, got", self.__header.opcode
        return self._opcode

    def parse(self, real_offset):
        child_opcode = struct.unpack_from('B', self._buff, self._offset_begin + self._size)
        node = node_types[child_opcode[0] & 0x0f](self._buff, self._offset_begin + self._size, self._total_size, self.parent)
        self._offset_begin = node.parse(self._offset_begin + self._size)
        return self._offset_begin

    def isValid(self):
        if self.__header.unknown1 != 1 or self.__header.unknown2 != 1:
            return False
        return True

# -24 : taille du chunk header, qui n'est pas stocke dans __buff
class TemplateNode(XmlNode):
    def __init__(self, buff, offset, total_size, parent):
        XmlNode.__init__(self, buff, offset, 10, 0x0c, total_size)

        self.parent = parent

        self.__header = XMLNode0x0c(buff, offset)
        if (self.__header.opcode & 0x0f) != 0x0c:
            print "Template opcode is wrong, got " , self.__header.opcode

    def parse(self, real_offset):
        tmp_offset = self.__header.Pointer
        template = TemplateXml(self._buff, tmp_offset)

        offset_sub_array = 0

        if self.__header.Pointer < real_offset:
            offset_sub_array = real_offset + self.__header.templateSize()
        else:
            offset_sub_array = template.size + template.templateSize() + self.__header.Pointer
        sub_array = SubArray(self._buff, offset_sub_array, self.parent)
        sub_array.getDataCount()
        sub_array.getValues()

        self.parent.sub_arrays.append(sub_array)

        template_root_node = RootNode(self._buff,\
                                          tmp_offset + template.templateSize(),\
                                          self._total_size, self.parent)
        offset = template_root_node.parse(real_offset)
        self.parent.sub_arrays.pop()
        return offset

class Node(XmlNode):
    def __init__(self, buff, offset, total_size, parent):
        XmlNode.__init__(self, buff, offset, 11, 0x01, total_size)
        self.parent = parent
        self.__header = XMLNode0x01(buff, offset)
        self.__hasAttr = False
        self.__name = ""
        self.__tag = ""
        if self.__header.opcode & 0xf0 == 0x40:
            self.__hasAttr = True
        self._attr_list = {}

    def parse(self, real_offset):
        offset = self.tagName(real_offset)

        if self.__hasAttr:
            offset = self.getAttrs(offset)
        offset = self.closeTag(offset)

        if self.parent.root == None:
            self.parent.root = Element(self.__name, self._attr_list)
            self.parent.nodes.append(self.parent.root)
        else:
            parent_elem = self.parent.nodes[len(self.parent.nodes) - 1]
            new_elem = SubElement(parent_elem, self.__name, self._attr_list)
            self.parent.nodes.append(new_elem)

        if self.__tag == "/>":
            self.parent.nodes.pop()
            return offset
        opcode = struct.unpack_from('B', self._buff, offset)[0]
        while opcode & 0x0f != 0x04:
            offset = self.getChildren(offset, real_offset) #if any ...
            opcode = struct.unpack_from('B', self._buff, offset)[0]
        self._offset_begin = offset + 1

        self.parent.nodes.pop()
        return offset + 1

    def closeTag(self, offset):
        tag = struct.unpack_from('B', self._buff, offset)[0]

        if ((tag & 0x0f) != 0x02) and ((tag & 0x0f) == 0x04) and ((tag & 0x0f) == 0x03):
            print "The closing tag is invalid"
        if (tag & 0x0f) == 0x03:
            self.__tag = "/>"
        return offset + 1

    def tagName(self, real_offset):
        tmp_offset = self.__header.Pointer
        tag_infos = StringInfos(self._buff, tmp_offset)
        tag_name = self._buff[tmp_offset + tag_infos.templateSize():tmp_offset + tag_infos.templateSize() + tag_infos.len * 2]
        self.__name = str(unicode(tag_name.decode('utf-16', 'replace')))
        tmp_offset += tag_infos.templateSize() + tag_infos.len * 2
        if self.__hasAttr:
            tmp_offset += 6
        else:
            tmp_offset += 2

        if self.__header.Pointer < real_offset:
            if self.__hasAttr:
                return self.__header.offset + 4 + self.__header.templateSize()
            else:
                return self.__header.offset + self.__header.templateSize()
        return tmp_offset

    def getAttrs(self, offset):
        tag_header = XMLNode0x06(self._buff, offset)
        while (tag_header.opcode & 0x0f) == 0x06: # a tag is found
            attr_infos = StringInfos(self._buff, tag_header.pointer) # should be dynamic
            tmp_offset = tag_header.pointer + attr_infos.templateSize()
            attr_name = self._buff[tmp_offset:tmp_offset + attr_infos.len * 2]
            attr_name_str = str(unicode(attr_name.decode('utf-16', 'replace')))

            if tmp_offset < offset:
                offset += tag_header.templateSize()
            else:
                offset = tmp_offset
                offset += (attr_infos.len * 2) + 2
    
            val_infos = XMLNode0x05(self._buff, offset)
            attr_val = ""
            if (val_infos.opcode % 0x0f) == 0x05:
                offset += val_infos.templateSize()
                attr_val = str(unicode(self._buff[offset:offset + val_infos.len * 2].decode('utf-16', 'replace')))
                #print attr_val                
                offset += (val_infos.len * 2)
                tag_header = XMLNode0x06(self._buff, offset)
            elif (val_infos.opcode % 0x0f) == 0x0e or (val_infos.opcode & 0x0f == 0x0d):
                val_infos = XMLNode0x0e(self._buff, offset)

                attr_val = self.parent.sub_arrays[len(self.parent.sub_arrays) - 1].substitute(val_infos.index)

                offset += val_infos.templateSize()
                tag_header = XMLNode0x06(self._buff, offset)

            if attr_val != "":
                self._attr_list[str(attr_name_str)] = str(attr_val)

            if self.__name == "Provider" and attr_name_str == "Name":
                self.parent.source = attr_val
            elif self.__name == "TimeCreated" and attr_name_str == "SystemTime":
                self.parent.date = attr_val                
        return offset

    def getChildren(self, offset, real_offset):
        opcode = struct.unpack_from('B', self._buff, offset)[0]
        try:
            node = node_types[opcode & 0x0f](self._buff, offset, self._total_size,\
                                                 self.parent)
            offset = node.parse(offset)
        except KeyError:
            if (opcode & 0x0f == 0x0e) or (opcode & 0x0f == 0x0d):
                val_infos = XMLNode0x0e(self._buff, offset)

                index = self.parent.sub_arrays[len(self.parent.sub_arrays) - 1].substitute(val_infos.index)
                if index == "":
                    index = " "
                xml_node = self.parent.nodes[len(self.parent.nodes) - 1]

                xml_node.text = index
                if self.__name == "EventID":
                    self.parent.id = int(index)
                elif self.__name == "Level":
                    self.parent.lvl = int(index)

                offset += 4
                opcode = struct.unpack_from('B', self._buff, offset)[0]
                if (opcode & 0x0f) == 0x04:
                    return offset
                    offset += 1
                return offset
            elif (opcode & 0x0f) == 0x05:
                stri = XMLNode0x05(self._buff, offset)
                offset += stri.templateSize()
                attr_val = str(unicode(self._buff[offset:offset + stri.len * 2].decode('utf-16', 'replace')))
                xml_node = self.parent.nodes[len(self.parent.nodes) - 1]
                xml_node.text = str(attr_val)

                return offset + stri.len * 2
        return offset

node_types = {
    0x00:RootNode,
    0x01:Node,
    0x0C:TemplateNode
}

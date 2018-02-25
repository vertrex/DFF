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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 
import pyregfi
from struct import unpack
from ctypes import pointer, byref, create_string_buffer, c_uint32, c_bool

from dff.api.vfs.libvfs import Node
from dff.api.types.libtypes import Variant, VList, VMap, MS64DateTime 

from dff.modules.winreg.pathmanager import pathManager
from dff.modules.winreg.regtype import regtype

class ValueNode(Node):
  REGFI_BIG_DATA_MIN_LENGTH = 0xC
  def __init__(self, rhive, parent, node, value):
     mfso = rhive.mfso
     if value.name:
       name = value.name.encode('utf-8')
     else:
       name = "default"
     self.__type = value.type
     self.__chunk = None
     try:
       size = self.fetchData(value.data_off, value.data_size, value.data_in_offset, value, rhive)
     except Exception as e:
        size = 0
     if not size:
       size = 0
     Node.__init__(self, name, size, parent, mfso)
     self.__disown__()    

  def fetchData(self, voffset, length, data_in_offset, value, rhive):
     self.__offset = voffset 
     if data_in_offset:
       self.__chunk = [(value.offset + 0xC, length,)]
       return length 
     else:
        offset = voffset + pyregfi.REGFI_REGF_SIZE 
        max_size = pyregfi.regfi.regfi_calc_maxsize(value._hive.file, offset)
        if max_size < 0:
           return 
        cell_length = c_uint32()
        unalloc = c_bool()
        if not pyregfi.regfi.regfi_parse_cell(pointer(value._hive.raw_file), c_uint32(offset), None, c_uint32(0), byref(cell_length), byref(unalloc)):
           return 
        cell_length = cell_length.value
        if (cell_length & 0x00000007) != 0:
           return 
        if cell_length > max_size:
           return 
        if cell_length - 4 < length:
           if rhive.major_version >= 1 and rhive.minor_version >= 5:
            try: 
             return self.parse_big_data(value, offset, length, cell_length)
            except Exception as e:
             return 
           else:
             length = cell_length - 4
        return self.parse_data(offset, length)

  def parse_data(self, offset, length):
     self.__chunk = [(offset + 4, length,)]
     return length

  def parse_big_data(self, value, offset, data_length, cell_length): 
     bd_header = self.parse_big_data_header(value._hive.file, offset, cell_length, value)
     if not bd_header:
        return

     num_chunks = unpack('H', bd_header[0x2:0x2+2])[0]
     indirect_offset = unpack('I', bd_header[0x4:0x4+4])[0] + pyregfi.REGFI_REGF_SIZE
     indirect_ptrs = self.parse_big_data_indirect(value, indirect_offset, num_chunks)
     if not indirect_ptrs:
        return

     range_list = self.parse_big_data_cells(value, indirect_ptrs, num_chunks)   
     self.__chunk = []
     size  = 0
     for (off, sz) in range_list:
       sz -= 8
       if size + sz > data_length:
          sz = data_length - size
       size +=  sz
       self.__chunk.append((off + 4, sz,))
     return size   

  def parse_big_data_cells(self, value, offsets, num_chunks):
     range_list = []
     for i in range(0, num_chunks):
        chunk_offset = offsets[i] + pyregfi.REGFI_REGF_SIZE
        cell_length = c_uint32()
        unalloc = c_bool()
        if not pyregfi.regfi.regfi_parse_cell(pointer(value._hive.raw_file), c_uint32(chunk_offset), None, c_uint32(0), byref(cell_length), byref(unalloc)):
          return None
        range_list.append( (chunk_offset, cell_length.value,) )
     return range_list 

  def parse_big_data_indirect(self, value, offset, num_chunks):
     max_size = pyregfi.regfi.regfi_calc_maxsize(value._hive.file, offset)
     if ((max_size < 0) or (num_chunks*4 + 4 > max_size)):
        return None

     buff = create_string_buffer(num_chunks * 4)
     indirect_length = c_uint32()
     unalloc = c_bool()
     if not pyregfi.regfi.regfi_parse_cell(pointer(value._hive.raw_file), c_uint32(offset), buff, num_chunks*4, byref(indirect_length), byref(unalloc)):
       return None 
 
     return unpack('I'*num_chunks, buff)

  def parse_big_data_header(self, file, offset, max_size, value):
     if ValueNode.REGFI_BIG_DATA_MIN_LENGTH > max_size:
        return None
     buff = create_string_buffer(ValueNode.REGFI_BIG_DATA_MIN_LENGTH)
     cell_length = c_uint32()
     unalloc = c_bool()
     if not pyregfi.regfi.regfi_parse_cell(pointer(value._hive.raw_file), c_uint32(offset), buff, c_uint32(ValueNode.REGFI_BIG_DATA_MIN_LENGTH), byref(cell_length), byref(unalloc)):
        return None
     
     if (buff[0] != 'd') or (buff[1] != 'b'):
        return None
     return buff

  def fileMapping(self, fm):
     if self.__chunk:
       currentOffset = 0
       for (offset, size) in self.__chunk:
         fm.push(currentOffset, size, self.fsobj().hive, offset)
         currentOffset += size

  def _attributes(self):
      try:
        attr = VMap()
        attr['type'] = Variant(regtype[self.__type])
        data = self.decodeData()
        if data != None:
          attr['data'] = data
      except Exception as e:
        pass
      return attr

  def decodeData(self):
     size = self.size()
     vfile = self.open()
     data = vfile.read(size)
     vfile.close()
     if size <= 4:
       if size == 4:
         if  self.__type != 5:
           return Variant(unpack('<I', data)[0])
         else: 
           return Variant(unpack('>I', data)[0])
       elif size == 1:
         return Variant(unpack('B', data)[0])
       elif size == 2:
         return Variant(unpack('H', data)[0])
       elif size == 3:
         return Variant(unpack('I', data + '\x00')[0])
       return
     try:
       return getattr(self, 'decode_' + regtype[self.__type])(data)
     except Exception as e:
        pass
     return None
 
  def decode_REG_SZ(self, data):
     return Variant(unicode(data, 'UTF-16').encode('UTF-8'))
  
  def decode_REG_EXPAND_SZ(self, data): 
     return Variant(unicode(data, 'UTF-16').encode('UTF-8'))
 
  def decode_REG_LINK(self, data):
     return Variant(unicode(data, 'UTF-16').encode('UTF-8'))
   
  def decode_REG_DWORD(self, data):
     return Variant(unpack('<I', data[0:4])[0]) 

  def decode_REG_DWORD_BIG_ENDIAN(self, data):
     return Variant(unpack('>I', data[0:4])[0]) 
 
  def decode_REG_QWORD(self, data):
     return Variant(unpack('Q', data[0:8])[0])

  def decode_REG_MULTI_SZ(self, data):
     vlist = VList()  
     for line in unicode(data, 'UTF-16').split('\x00'): 
        if line:
          vlist.append(Variant(line.encode('UTF-8')))
     return vlist
   
  def icon(self):
    return (":password.png")

class KeyNode(Node):
  def __init__(self, mfso, parent, name, node,  key):
    Node.__init__(self, name, key.cell_size, parent, mfso)
    self.__disown__()
    self.timestamp = key.mtime
    self.offset = key.offset

  def fileMapping(self, fm):
    fm.push(0, self.size(), self.fsobj().hive, self.offset)

  def _attributes(self):
     attr = VMap()
     vt = MS64DateTime(self.timestamp)
     vt.thisown = False
     vmodified = Variant(vt)
     attr["modified"] = vmodified
     return attr

  def dataType(self):
    return "registry/key"

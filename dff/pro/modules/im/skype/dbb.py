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
#  Solal Jacob <sja@arxsys.fr>
#

from struct import unpack

from dff.api.module.module import Module, Script
from dff.api.module.manager import ModuleProcessusHandler, ModuleProcessusManager
from dff.api.types.libtypes import Argument, typeId

from dbbrecord import SkypeMessageDBB, SkypeChatDBB, SkypeChatMemberDBB, SkypeCallDBB, SkypeCallMemberDBB, SkypeContactGroupDBB, SkypeAccountDBB, SkypeTransferDBB, SkypeContactDBB

class DBBManager(ModuleProcessusHandler):
  def __init__(self, moduleName):
     ModuleProcessusHandler.__init__(self, moduleName)
     self.__dbbs = {}

  def update(self, processus):
     self.__dbbs[processus] = processus.node

  def processus(self):
     return self.__dbbs

  def childrenOf(self, mountpoint):
     dbbs = []
     for dbb, path in self.__dbbs.iteritems():
       if path.absolute().find(mountpoint.absolute()) ==  0:
         dbbs.append(dbb)
     return dbbs
 
ModuleProcessusManager().register(DBBManager('DBB'))

class DBBParser(object):
  factories = {
    'chatmsg' : SkypeMessageDBB,
    'chat' : SkypeChatDBB,
    'chatmember': SkypeChatMemberDBB,
    'call' : SkypeCallDBB,
    'callmember' : SkypeCallMemberDBB,
    'contactgroup' : SkypeContactGroupDBB,
    'profile' : SkypeAccountDBB,
    'transfer' : SkypeTransferDBB,
    'user' : SkypeContactDBB,
  }

  typeInt = 0x00
  typeText = 0x03
  typeBlob = 0x04
  def __init__(self, node, factory = None):
    self.factory = factory
    self.f = node.open()
    (self.fname, self.recordSize) = self.fileNameRecordSize(node.name())
    self.maximumRecordID = (node.size() - 1) / self.recordSize + 1

  @staticmethod
  def fileNameRecordSize(name):
     size = ''
     fname = ''
     nameEnd = False
     for c in name:
       if c.isdigit():
         nameEnd = True
         size += c 
       elif nameEnd == False:
         fname += c
     size = int(size)
     return (fname, size + 8)

  @staticmethod
  def instance(node):
    name, size = DBBParser.fileNameRecordSize(node.name())
    try:
      factory = DBBParser.factories[name]
    except KeyError:
      pass
    return DBBParser(node, factory)

  def read7bit(self, record, offset):
    code = 0
    shift = 0
    while True:
      char = ord(record[offset])
      code = code + ((char & 0x7F) << shift)
      shift += 7
      offset += 1
      if char & 0x80 == 0:
        break
    return (code, offset)

  def readRecord(self, recordID):
    if recordID >= self.maximumRecordID:
      return None
    self.f.seek(self.recordSize * recordID)
    record = self.parseRecord(self.f.read(self.recordSize))
    if self.factory:
      return self.factory(record)
    return record

  def parseRecord(self, record):
    result = {}
    header, size, recordSequence, unknown1, unknown2 = unpack('<IIIIc', record[0:17])
    result[-1] = recordSequence
    if header != 0x6c33336c:
      raise Exception("Can't find header in record")
    offset = 17 
    while offset < size + 8:
      startOffset = offset
      dataType = ord(record[offset])
      offset += 1
      if dataType ==  DBBParser.typeInt:
        code, offset = self.read7bit(record, offset)
        value, offset = self.read7bit(record, offset)
      elif dataType == DBBParser.typeText:
        code, offset = self.read7bit(record, offset)
        end = record.find('\x00', offset)
        if end == -1:
          raise Exception("End of text data not found")
        value = record[offset:end]
        offset = end + 1
      elif dataType == DBBParser.typeBlob:
        code, offset = self.read7bit(record, offset)
        size, offset = self.read7bit(record, offset)
        value = record[offset:offset + size]
        offset = offset + size
      else:
        raise Exception ('Cant found field type %x', dataType)
      result[code] = value
      if offset <= startOffset:
        return result 
    return result

  def show(self):
    if self.factory:
      for record in self:
        for k, v in record.record().iteritems():
          try:
            print self.factory.field[k], " : ", v
          except KeyError:
            print k, " : ", v
        print '=' * 80

  def showUnknown(self):
    if self.factory:
      for record in self:
        for k, v in record.record().iteritems():
          try:
            x = self.factory.field[k]
          except KeyError as e:
            print 'Error unknown type for value ' + str(e) + ' on record : ' 
            print record.record()
        
  def __iter__(self):
    for recordID in range(0, self.maximumRecordID):
      yield self.readRecord(recordID)
  
  def __del__(self):
    self.f.close()

class DBB(Script):
  def __init__(self):
    Script.__init__(self, "DBB")

  def start(self, args):
     try:
       self.node = args['node'].value()
       self.dbb = DBBParser.instance(self.node)
     except Exception as e:
       print 'Exception: ', str(e)
     except KeyError:
       print 'DBB argument node not set' 

class dbb(Module):
  """This module parse old style Skype database (dbb), should be more or less compatible with Kazaa DBB too"""
  def __init__(self):
    Module.__init__(self, "dbb", DBB) 
    self.conf.addArgument({"name" : "node",
                           "description" : "DBB file to parse",
                           "input" : Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name" : "extension-type",
                          "type" : typeId.String,
                          "description" : "compatible extension",
                          "values" : ["dbb"]})
    self.tags = "Databases"
    self.icon = ":database"

# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
#  Jeremy MOUNIER <jmo@digital-forensic.org>
# 

from dff.api.module.manager import ModuleProcessusHandler

class MsiecfManager(ModuleProcessusHandler):
  def __init__(self, name):
    ModuleProcessusHandler.__init__(self, name)
    self.indexs = {}

  def update(self, processus):
      itype = processus.indexType()
      if itype != None:
        self.indexs[processus] = itype

  def getAllRecords(self, indextype, rectype):
    responses = []
    for index, itype in self.indexs.iteritems():
      res = {}
      res["index"] = index.node
      res["data"] = [] 
      if itype == indextype:
        if rectype == "VALID":
          records = index.validRecords()
          if len(records):
            res["data"].extend(records)
        elif rectype == "INVALID":
          res["data"].extend(index.invalidRecords())
        elif rectype == "UNKNOWN":
          res["data"].extend(index.unknownRecords())
      responses.append(res)
#    print responses
    return responses


  def getRecords(self, indextype, rectype, deleted=False, root = None):
    # XXX implement deleted, leak records 
    responses = []
    rootAbsolute = root.absolute()
    for index, itype in self.indexs.iteritems():
      if index.node.absolute().find(rootAbsolute) == 0:
        if itype == indextype:
          if rectype == "VALID":
            responses.extend(index.validRecords())
          elif rectype == "INVALID":
            responses.extend(index.invalidRecords())
          elif rectype == "UNKNOWN":
            responses.extend(index.unknownRecords())
    return responses

  def getCacheRecords(self, root):
    responses = []
    rootAbsolute = root.absolute()
    for index, itype in self.indexs.iteritems():
      if index.node.absolute().find(rootAbsolute) == 0:	
        if itype == "TEMP":
          responses.append(index.cacheRecords())
    return responses
    

  def getRootNodePath(self, record):
    return record.vfile.node().absolute()

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
#  Solal Jacob <sja@digital-forensic.org>
# 

__dff_module_hash_version__ = "1.0.0"

import hashlib, os, threading

from dff.api.vfs import vfs 
from dff.api.module.script import Script 
from dff.api.module.module import Module 
from dff.api.types.libtypes import Variant, VMap, VList, Parameter, Argument, typeId
from dff.api.vfs.libvfs import AttributesHandler, VLink

class HashSets(object):
  KNOWN_GOOD = True
  KNOWN_BAD = False
  def __init__(self):
     self.hsets = []

  def add(self, hsetpath, hsettype):
     for hid in xrange(0, len(self.hsets)):
	hset = self.hsets[hid]
        if hset.path == hsetpath:
	  if hset.knownGood  != hsettype:
	    if hset.knownGood == self.KNOWN_GOOD:
	      print 'Hash set ' + str(hsetpath) + ' was already set as good, keeping old value'
	    else:
	      print 'Hash set ' + str(hsetpath) + ' was already set as bad, keeping old value'
	  return hid
     try:
       self.hsets.append(HashSet(hsetpath, hsettype))
     except RuntimeError:
	raise
     return len(self.hsets) - 1

  def get(self, hsetid):
     return self.hsets[hsetid]

  def find(self, baseIDs, hash_value):
      foundinbase = []
      for baseID in baseIDS:
	 if getBase(baseIds).find(hash_value):
	   foundinbase += baseID
      return foundinbase

class HashSet(object):
  def __init__(self, hash_set, hsettype):
     self.hashType = None
     self.path = hash_set
     self.knownGood = hsettype
     if len(hash_set.split('\\')) != 1:
	self.name = hash_set.split('\\')[-1]
     elif len(hash_set.split('/')) != 1:
	self.name = hash_set.split('/')[-1]
     else:
	 self.name = hash_set
     self.size = os.path.getsize(hash_set)
     self.gettype()

  def algo(self):
     return self.hashType

  def gettype(self):
     f = open(self.path)
     self.headerSize = 0
     self.lineSize = len(f.readline())
     self.hashSize = self.lineSize - 1
     for algo in hashlib.algorithms:
	hobj = getattr(hashlib, algo)
	if (hobj().digestsize * 2) == self.hashSize:
	   self.hashType = algo
	   continue
     if self.hashType == None:
	f.close()
	raise RuntimeError("Hash set " + self.path + " type not found")
     self.len = (self.size - self.headerSize) / self.lineSize
     f.close()

  def getLine(self, file, line):
     file.seek(self.headerSize + (line * self.lineSize), 0)
     return int(file.read(self.hashSize), 16)

  def find(self, h):
     file = open(self.path)
     h = int(h, 16)
     found = self.binSearch(file, h, 0, self.len - 1)
     file.close()
     return found

  def binSearch(self, file, sha, low, high):
     while low <= high:
	mid = (low + high) / 2
	fsha = self.getLine(file, mid)
	if fsha < sha:
	  low = mid + 1
        elif fsha > sha:
	   high = mid - 1
        else: 
	   file.close()
	   return True
     return False

  def __len__(self):
      return self.len


class HashInfo(object):
    def __init__(self):
       self.hashes = {}
       self.hsets = set()

class AttributeHash(AttributesHandler): 
    def __init__(self, parent, modname):
      self.__parent = parent
      AttributesHandler.__init__(self, modname)
      self.__lock = threading.Lock()
      self.__hashs = {}
      self.__disown__()	


    def count(self):
      self.__lock.acquire()
      _count = len(self.__hashs)
      self.__lock.release()
      return _count

    def hasId(self, node):
      self.__lock.acquire()
      ret = self.__hashs.has_key(node.uid())
      self.__lock.release()
      return ret


    def hasHash(self, node, algo):
      idx = node.uid()
      self.__lock.acquire()
      has_hash = self.__hashs.has_key(idx) and self.__hashs[idx].hashes.has_key(algo)
      self.__lock.release()
      return has_hash


    def getHash(self, node, algo):
      """ return a hash already computed else None"""
      h = None
      idx = node.uid()
      self.__lock.acquire()
      if self.__hashs.has_key(idx):
        h = self.__hashs[idx].hashes[algo]
      self.__lock.release()
      return h

    def setHash(self, node, algo, h):
      idx = node.uid()
      self.__lock.acquire()
      if self.__hashs.has_key(idx):
        hashInfo = self.__hashs[idx]
      else:
        hashInfo = HashInfo()
        self.__hashs[idx] = hashInfo
      hashInfo.hashes[algo] = h
      self.__lock.release()
      node.attributesHandlers().updateState()


    def setKnown(self, node, setId):
      idx = node.uid()
      self.__lock.acquire()
      if self.__hashs.has_key(idx):
        hashInfo = self.__hashs[idx]
      else:
        hashInfo = HashInfo()
        self.__hash[idx] = hashInfo
      hashInfo.hsets.add(setId)
      self.__lock.release()
      node.attributesHandlers().updateState()


    def __getHashes(self, node):
       hdic = {}
       calclist = []
       idx = node.uid()
       hashes = None
       self.__lock.acquire()
       if self.__hashs.has_key(idx):
         hashes = self.__hashs[idx].hashes
       self.__lock.release()
       if hashes != None:
         for h in hashes:
	    if hashes[h] == None:
	      calclist.append(h)
	    else:
	      hdic[h] = hashes[h]
         if len(calclist):
           hinstances = self.__parent.calc(node, calclist)
           for hinstance in hinstances:
             hdic[hinstance.name] = hinstance.hexdigest()
         return hdic
       else:
         return {}


    def attributes(self, node):
       m = VMap()
       idx = node.uid()
       self.__lock.acquire()
       if self.__hashs.has_key(idx):
         hashInfo = self.__hashs[idx]
         hsets = hashInfo.hsets
       else:
         hsets = []
       self.__lock.release()
       hashes = self.__getHashes(node)
       for algo in hashes:
	  v = Variant(str(hashes[algo]))
	  m[str(algo)] = v
       if len(hsets):
	 knownBad = []
	 knownGood = []
         for setId in hsets:
           hset = self.__parent.getHashSetFromId(setId)
           if hset.knownGood:
             knownGood.append(hset)
           else:
             knownBad.append(hset)
         if len(knownBad):
	   badList = VList()
	   for badSet in knownBad:
	     vname = Variant(badSet.name)
	     badList.append(vname)
 	   m["known bad"] = badList
	 if len(knownGood):
	   goodList = VList()
	   for goodSet in knownGood:
	     vname = Variant(goodSet.name)
	     goodList.append(vname)
	   m["known good"] = goodList
       return m

    def __del__(self):
	pass

class HASH(Script): 
    def __init__(self):
      Script.__init__(self, "hash")   
      self.vfs = vfs.vfs()
      self.__lock = threading.Lock()
      self.__cacheSize = 0
      self.__hashSets = HashSets()
      self.__knownBadFiles = 0
      self.__knownGoodFiles = 0
      self.__errorFiles = 0
      self.__skippedFiles = 0
      self.attributeHash = AttributeHash(self, "hash")


    def start(self, args):
      node = args["file"].value()
      if isinstance(node, VLink):
        node = node.linkNode()
      self.__setResults()
      if node.size() == 0:
          self.__lock.acquire()
          self.__skippedFiles += 1
          self.__lock.release()
          self.__setResults()
          return
      if args.has_key("skip_size"):
        maxSize = args["skip_size"].value()
        if (node.size() > maxSize):
          self.__lock.acquire()
          self.__skippedFiles += 1
          self.__lock.release()
          self.__setResults()
          return
      if args.has_key("low_cache-limit"):
        self.__cacheSize = args["low_cache-limit"].value()
      else:
        self.__cacheSize = 0
      currentHashSets = self.__getHashSets(args)
      algorithms = []
      if args.has_key("algorithm"):
        algos = args["algorithm"].value()
        for algo in algos:
          algo = algo.value()
          algorithms.append(algo)
      elif len(currentHashSets) == 0:
        algorithms = ["sha1"]
      if len(currentHashSets):
        for hsetId in currentHashSets:
          self.__lock.acquire()
          algo = self.__hashSets.get(hsetId).algo()
          self.__lock.release()
          algorithms.append(algo)
      self.__run(node, set(algorithms), currentHashSets)
      self.__setResults()

    def getHashSetFromId(self, setId):
      self.__lock.acquire()
      hset = self.__hashSets.get(setId)
      self.__lock.release()
      return hset

    def calc(self, node, algorithms):
      buffsize = 10*1024*1024
      hinstances = []
      for algo in algorithms:
        if hasattr(hashlib, algo):
          func = getattr(hashlib, algo)
          instance = func()
          hinstances.append(instance)
      if len(hinstances):
        try :
          f = node.open()
        except IOError as e:
          f.close()
          self.__lock.acquire()
          self.__errorFiles += 1
          self.__lock.release()
          return []
        buff = f.read(buffsize)
        total = len(buff)
        name = node.name()
        size = node.size()
        while len(buff) > 0:
          self.stateinfo = name + " %d" % (total / float(size) * 100) + "%"
          for hinstance in hinstances:
            hinstance.update(buff)
          try :
            buff = f.read(buffsize)
            total += len(buff)
          except IOError as e:
            print "Error hashing files " + str(node.absolute()) + " can't read between offsets " + str(total) + " and " + str(total+buffsize)
            self.__lock.acquire()
            self.__errorFiles += 1
            self.__lock.release()
            f.close()
            return []
        self.stateinfo = name + " %d" % (total / float(size) * 100) + "%"
        f.close()
        return hinstances
      else:
        return []


    ###
    ###  Private methods
    ###

    def __run(self, node, algorithms, currentHashSets):
      doalgo = []
      hashmap = {}
      if not self.attributeHash.hasId(node):
        node.registerAttributes(self.attributeHash)
      for algo in algorithms:
        if not self.attributeHash.hasHash(node, algo):
          doalgo.append(algo)
          hashmap[algo] = None
        else:
          _hash = self.attributeHash.getHash(node, algo)
          hashmap[algo] = _hash
      if len(doalgo):
        hinstances = self.calc(node, doalgo)
        if len(hinstances) > 0:
          for hinstance in hinstances:
            xdigest = hinstance.hexdigest()
            hashmap[hinstance.name] = xdigest
            if node.size() > self.__cacheSize:
              self.attributeHash.setHash(node, hinstance.name, xdigest)
            else:
              self.attributeHash.setHash(node, hinstance.name, None)
        else:
          self.__lock.acquire()
          self.__skippedFiles += 1
          self.__lock.release()
      for htype in hashmap.iterkeys():
        for hsetid in currentHashSets:
          hset = self.__hashSets.get(hsetid)
          if htype == hset.algo():
            if hset.find(hashmap[htype]):
              self.attributeHash.setKnown(node, hsetid) 
              if hset.knownGood:
                self.__knownGoodFiles += 1
                node.setTag("known good")
              else:
                self.__knownBadFiles += 1
                node.setTag("known bad")


    def __setResults(self):
      self.__lock.acquire()
      try:
        v  = Variant(self.attributeHash.count())
        self.res["hashed files"] = v
        v = Variant(self.__knownGoodFiles)
        self.res["known good files"] = v
        v = Variant(self.__knownBadFiles)
        self.res["known bad files"] = v
        v = Variant(self.__skippedFiles)
        self.res["skipped files"] = v
        v =  Variant(self.__errorFiles)
        self.res["Errors"] = v
      except:
        pass
      self.__lock.release()


    def __getHashSets(self, args):
      currentHashSets = set()
      if args.has_key("known_good"):
        goodBases = args["known_good"].value()
        for base in goodBases:
          self.__lock.acquire()
          try:
            base = self.__hashSets.add(base.value().path, HashSets.KNOWN_GOOD)
            currentHashSets.add(base)
          except RuntimeError as error:
            print error
          self.__lock.release()
      if args.has_key("known_bad"):
        badBases = args["known_bad"].value()
        for base in badBases:
          self.__lock.acquire()
          try :
            base = self.__hashSets.add(base.value().path, HashSets.KNOWN_BAD)
            currentHashSets.add(base)
          except RuntimeError as error:
            print error
          self.__lock.release()
      return currentHashSets

 
    
class hash(Module):
    """Processes cryptographic hash of a file and sets results as file attributes.
    ex: hash /myfile"""
    def __init__(self):
        Module.__init__(self, "hash", HASH)
        self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                               "name": "file",
                               "description": "file to process"
                               })
        self.conf.addArgument({"input": Argument.Optional|Argument.List|typeId.String,
                               "name": "algorithm",
                               "description": "algorithm(s) used to process cryptographic hash",
                               "parameters": {"type": Parameter.NotEditable,
                                              "predefined": ["sha1", "md5", "sha224", "sha256", "sha384", "sha512"]}
                               })
	self.conf.addArgument({"input": Argument.Optional|Argument.List|typeId.Path,
			       "name": "known_good",
			       "description" : "Files containing a set of known good hashes",
			      }) 
 	self.conf.addArgument({"input": Argument.Optional|Argument.List|typeId.Path,
			       "name": "known_bad",
			       "description" : "Files containing a set of known bad hashes",
			      })
        self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.UInt64,
			       "name": "skip_size",
                               "description" : "Each node with a size greater than or equal to skip_size will not be processed"})
        self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.UInt64,
			       "name": "low_cache-limit",
                               "description" : "Set a low bound size for the cache.\nEach node with a size lesser or equal to low_cache-limit will not be cached,\nthis could lower the RAM usage on a dump with a very huge amount of nodes"
                             })
        self.flags = ["single", "generic"]
        self.tags = "Hash"
        self.icon = ":filehash"

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
#  Jeremy MOUNIER <jmo@digital-forensic.org>
# 
import re

from dff.api.module.manager import ModuleProcessusHandler

class RegistryManager(ModuleProcessusHandler):
  def __init__(self, moduleName):
    ModuleProcessusHandler.__init__(self, moduleName)
    self.registry = {}
#    self._hives = {}

  def update(self, processus):
     rtype = processus.regType()
     if rtype != None:
       self.registry[processus] = rtype
     # self._hives = {}
     # for proc, regtype in self.registry.iteritems():
     #   try:
     #     self._hives[regtype[0]].append(regtype[1])
     #   except:
     #     self._hives[regtype[0]] = []
     #     self._hives[regtype[0]].append(regtype[1])
 
  def splitPath(self, path):
    if path:
      return path.split('\\')
    else:
      return None

  def getAllKeys(self, query):
    # Compatible with only {"KEY_PATH" : {"values" :'', 'description' : ''}}
    # Returns a list containing from each query (key path query) a dictionnary of key : values
    results = []
    for keypath, conf in query.iteritems():
      if not isinstance(conf, dict):
        return None
      spath = self.splitPath(keypath)
      tag = self.getTag(spath)
      res = {}
      res["query"] = keypath
      res["description"] = conf["description"]
      res["keys"] = {}
      for proc, (rtag, node) in self.registry.iteritems():
        if rtag.capitalize() == tag.capitalize():
          try:
            hive, keys = self.searchRegExp(spath, proc)
            for key in keys:
              values = self.dumpValues(key, conf["values"])
              values["KeyModifiedTime"] = key.mtime
              values["Hive"] = node
              res["keys"][key.name] = values
          except TypeError:
            pass
      results.append(res)
    return results

  def dumpValues(self, key, requested):
    values = {}
    if key.values:
      if len(requested) == 1 and requested[0] == '*':
        for v in key.values:
          values[v.name] = v.fetch_data()
      else:
        for value in key.values:
          for v in requested:
            if re.match(v, value.name, re.IGNORECASE):
              values[value.name] = value.fetch_data()
      return values
    else:
      return {}


  def getKeys(self, kvdict, root):
    # Dict of key path : value list 
    # or Dict of key path : Dict { 'values' : '', 'description', ...}
    responses = []
    rkeys = {}
    rootAbsolute = root.absolute()
    for key, values in kvdict.iteritems():
      if isinstance(values, dict):
	values = values['values']
      spath = self.splitPath(key)
      tag = self.getTag(spath)
      if tag:
        for regmod, (rtag, node) in self.registry.iteritems():
	  if node.absolute().find(rootAbsolute) == 0:
            if rtag.capitalize() == tag.capitalize():
              args = self.searchRegExp(spath, regmod)
	      if args:
	        phive, klist = args
                if klist:
                  resp = self.formatToResponse(phive, klist, values, tag, key)
                  responses.extend(resp)
    return RegKeyManager(responses)

  def formatToResponse(self, phive, keys, values, tag, query = None):
    responses = []
    if not values or not keys:
      return responses
    for k in keys:
      responses.append(RegKey(phive, k, values, tag, query))
    return responses

  def searchRegExp(self, spath, regmod):
    phive = regmod.getHive()
    if phive.hive:
      rootkey = phive.hive.root 
    else: 
      return None
    if rootkey:
      keys = [rootkey]
      for curkey in spath:
        nkeys = []
        match = curkey.find('*')
        for k in keys:
	  try:
            for sk in k.subkeys:
              if match >= 0:
                pattern = curkey.replace('*', '.*')
              else:
                pattern = curkey
	      pattern += '$'
              if re.match(pattern, sk.name, re.IGNORECASE):
                nkeys.append(sk)
	  except :	
		pass #pyregfi ERROR check XXX
#          else:
#            return None
          keys = nkeys[:]
      return (phive, keys) #we must have a ref to hive to avoid deleting it
    else:
      return None

  def getTag(self, spath):
      if spath[0] == "HKLM":
        tag = spath[0] + "\\" + spath[1]
        # Remove node tag name (ex: SYSTEM) from path
        spath.remove(spath[1])
      elif spath[0] in ["HKU", "HKUCL"]:
        tag = spath[0]
      else:
        return None
      # Remove
      spath.remove(spath[0])
      return tag

class RegKey:
  def __init__(self, phive, key, vlist, tag, query = None):
    self._key = key
    self._vlist = vlist
    self._tag = tag
    self.query = query
    self.mtime = self._key.mtime
     
    self.phive = phive

    setattr(self, "name", self._key.name)
    setattr(self, "hive", self._key._hive._fh.node()) #XXX sans () fonction

  def parent(self):
     return self._key.get_parent()

  def path(self):
     c = self._key.get_parent()
     path = [c.name]
     while c.get_parent():
	path.insert(0, c.name)
	c = c.get_parent()
     return '\\'.join(path)

  def values(self):
    values = []
    if self._key.values:
      if len(self._vlist) == 1 and self._vlist[0] == '*':
        for v in self._key.values:
          values.append(RegValue(self._key, v))
      else:
        for value in self._key.values:
          for v in self._vlist:
            if re.match(v, value.name, re.IGNORECASE):
              values.append(RegValue(self._key, value))
      return values
    else:
      return None


class RegValue:
  def __init__(self, key, value):
    self._key = key
    self._value = value

    setattr(self, "name", self._value.name)

  def data(self):
    return self._value.fetch_data()

  def __unicode(self):
    return getattr(self, "name")


class RegKeyManager:
  def __init__(self, RegKeyList):
    self._keys = RegKeyList

  def __iter__(self):
    return iter(self._keys)

  def split(self):
    response = {}
    for key in self._keys:
      if key.hive.absolute() in response:
        response[key.hive].append(key)
      else:
        response[key.hive] = [key]
    return response

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
import sys, traceback
from struct import unpack

from dff.api.vfs.libvfs import VLink
from dff.api.types.libtypes import Variant, VMap, VList, Argument, typeId, DateTime, MS64DateTime, DosDateTime 

def getRecAttr(parent, attr):
   for attr in attr.split('.'):
      parent = getattr(parent, attr)
   return parent 

def ResolveAttributesMap(obj, attributesMap):
   attr = {}
   for k, v in attributesMap.iteritems():
      if type(v) == dict:
        try:
	  d = {}
	  for kk, vv in v.iteritems():
            try:
	       if (type(vv[0]) == str):
	         d[kk] = (getRecAttr(obj, vv[0]), vv[1])
	       else:
	         d[kk] = ((getRecAttr(obj, vv[0][0]), vv[0][1],), vv[1])
            except AttributeError, e:
	      pass 
	  if len(d):
	    attr[k] = (d, dict)
	except:
	  pass
      else:
	try:
	  if (type(v[0]) == str):
	     attr[k] = (getRecAttr(obj, v[0]), v[1])
	  else:
	    attr[k] = ((getRecAttr(obj, v[0][0]), v[0][1],), v[1]) 
	except AttributeError, e:
	  pass
   return attr

def attributesTypes(values, types):
   if (types == DateTime):
     val = DateTime(values)
     val.thisown = False
   elif (types == MS64DateTime):
     val = MS64DateTime(values)
     val.thisown = False
   elif (types == DosDateTime):
     val = DosDateTime(*values)
     val.thisown = False
   elif (types == int) or (types == long):
     if type(values) == str: #XXX strange ?  
       values = 0	
     val = types(values)
   elif (types == dict):
     val = VMap()
     for k, v in values.iteritems():
	vval = Variant(attributesTypes(*v))	
	val[k] = vval 
   elif (types == list):
     val = VList()
     for v in values:
       vval = Variant(attributesTypes(*v))
       val.append(vval) 
   elif (types == str):
      if type(values) == unicode:
	val = values.encode("UTF-8", "replace")
      else:
	val = str(values)
   elif (types == VLink): #return node is already created
      val = values 
   else:
     val = types(values)
   return val

def AttributesVMap(attrib):
   vattr = VMap()
   for attr, (values, types) in attrib.iteritems():
     try :
  	value = attributesTypes(values, types)
        try:
	  v = Variant(value)	   
        except :
          err_type, err_value, err_traceback = sys.exc_info()
          print traceback.format_exception_only(err_type, err_value)
          print traceback.format_tb(err_traceback)
    	  print "invalid variant value : " + str(value) + " type: " + str(type(value))
	vattr[attr] = v 
     except :
	#pass
        err_type, err_value, err_traceback = sys.exc_info()
        print traceback.format_exception_only(err_type, err_value)
        print traceback.format_tb(err_traceback)
	print "error on attr:" + str(attr) + " val: " + str(type(value)) 
   return vattr

def FlagsList(binAttributes, attributesFlags):
   s = bin(binAttributes).replace('0b','')[::-1]
   pad  = 32 - len(s)
   s += (32 - len(s))*'0'
   attributesList = []
   for i in xrange(0, len(s)):
      if int(s[i]):
	try:
	  attributesList.append((attributesFlags[i], str,))
	except IndexError:
	  pass
   return attributesList

class StructDef(object):
  def __init__(self, size, offset = None, stype = None, sshift = 0):
     self.ssize = size
     self.offset = offset ###virer le plus de self possible ca prend de la ram pour rien si ca sert pas apres
     self.stype = stype
     self.shift = sshift
     self.var = {}
    
class Struct(StructDef):
   def __init__(self, arch, file, structdef, data):
     self.arch = arch
     self.file = file
     self.structdef =  structdef
     
     StructDef.__init__(self, self.structdef.ssize, self.structdef.offset, self.structdef.stype)
     for varname, var in self.structdef.var.iteritems():
        setattr(self, varname, self.getVarValue(varname, data))

   def getVarValue(self,  varname, data):
     var = self.structdef.var[varname]
     intssize = var.ssize / 4
     try :
       if var.stype:
         if var.stype[0] == "*":
           pack = "I"
           (pointer, ) = unpack(pack, data[var.offset:var.offset + var.ssize])

           struct_addr = pointer + var.shift
           struct_type = var.stype[1:]
           struct_def = getattr(self.arch, struct_type)
           if struct_addr > 0 and (struct_addr + struct_def.ssize) <= self.file.node().size(): 
             self.file.seek(struct_addr)
             data = self.file.read(struct_def.ssize)
             struct_def.stype = struct_type
             struct_def.offset = 0
             try :
               rstruct = Struct(self.arch, self.file, struct_def, data[0: struct_def.ssize])
	       rstruct.pointer = pointer	
             except :
                error = sys.exc_info()
		#print error
		#print "error pointer to struct"
                return pointer
             return rstruct
           return pointer 
	 if len(var.stype) :
           sdef = getattr(self.arch, var.stype) 
           return Struct(self.arch, self.file, sdef, data[var.offset:var.offset + var.ssize])
	 elif var.ssize == 2:
	   pack = "H"
         elif var.ssize == 4:
           pack = "I"
	 #patch test for Q
	 elif var.ssize == 8:
	   pack = "Q"
       if var.ssize == 4: 
         pack = "I"
       elif var.ssize == 2:
	 pack = "H"
	#patch test for Q
       elif var.ssize == 8: #Q ==8 en 64 et en 32 bitrs ??
	 pack = "Q"
       else:
         pack = str(var.ssize) + "s"  
       (var_data, ) = unpack(pack, data[var.offset:var.offset + var.ssize])
       return var_data
     except AttributeError:
        return None


   def __str__(self):
     buff = ""
     for varname, var in self.structdef.var.iteritems():
        var = getattr(self, varname)
        if isinstance(var, int) or isinstance(var, long):
           buff += varname + ": " + hex(var) + "\n"
        elif isinstance(var, Struct):
           buff += varname + ":" + repr(var) +  "\n"
        else:
          buff += varname + ": " + str(var) + "\n"
     return buff
           

   def rstr(self):
     buff = ""
     for varname, var in self.structdef.var.iteritems():
        var = getattr(self, varname)
        if isinstance(var, int) or isinstance(var, long):
           buff += varname + ": " + hex(var) + "\n"
        elif isinstance(var, Struct):
           buff += varname + "\n{\n" + var.rstr() +  "}\n"
        else:
          buff += varname + ": " + str(var) + "\n"
     return buff

class Header(object):
  def __init__(self, header_descr):

    for name, val in header_descr["info"].iteritems():
      setattr(self, name, val)

    self.struct_def = header_descr["descr"]
    for struct_name, (struct_size, var_map) in self.struct_def.iteritems():
      setattr(self, struct_name, StructDef(struct_size, 0, struct_name)) 
      for valname, val in var_map.iteritems():
         st = getattr(self, struct_name)
         st.var[valname] = StructDef(*val)


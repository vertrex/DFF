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

from dff.modules.winreg.nodes import ValueNode, KeyNode 

class RHive():
    def __init__(self, node, mfso, verbose=False):
        self.node = node
        self.mfso = mfso
        self.verbose = verbose
        self.open()

    def __del__(self):
       del self.hive
       if self.vfile != None:
         self.vfile.close()
	 self.vfile = None

    def open(self):
        try:
            self.vfile = self.node.open()
        except :
	    self.mfso.stateinfo = "Error Opening " + str(self.node.absolute())
	    self.vfile = None
            self.hive = None
	try:
            self.hive = pyregfi.Hive(self.vfile)
            self.minor_version = self.hive.minor_version
            self.major_version = self.hive.major_version
            self.iterator = self.hive.__iter__()
            self.root = self.hive.root
            if self.verbose:
                self.countKeys()
        except:
            self.mfso.stateinfo = "Error Opening " + str(self.node.absolute())
	    self.vfile.close()
	    self.vfile = None
            self.hive = None

    def countKeys(self):
        self.mfso.stateinfo = "Compute hive keys"
        self.nkeys = 0
        self.parsedKeys = 0
        
        for key in self.iterator:
            self.nkeys += 1

    def updateCount(self):
        if self.verbose:
            self.parsedKeys += 1
            percent = (self.parsedKeys * 100) / self.nkeys
            self.mfso.stateinfo = str(percent) + "%"

    def mount(self):
        self.mfso.stateinfo = "Mounting Registry File System"
        self.registree(self.root, self.node)
        try:
            self.mfso.registerTree(self.node, self.rootnode)
        except AttributeError:
            self.mfso.stateinfo = "Error mounting " + str(self.node.absolute())
        self.mfso.stateinfo = ""    

    def registree(self, current, parent):
        if len(current.subkeys) > 0:
            if current.is_root():
                self.rootnode = knode = self.createNode(None, current)
            else:
                knode = self.createNode(parent, current)
	    try :
              for key in current.subkeys:
                self.registree(key, knode)
	    except :
		pass
        else:
            knode = self.createNode(parent, current)


    def createNode(self, parentNode, currentKey):
        if isinstance(currentKey.name, unicode):
            name = currentKey.name.encode('utf-8', 'replace')
        else:
            name =  currentKey.name.decode('latin1').encode("utf-8", "replace")
        knode = KeyNode(self.mfso, parentNode, name, self.node, currentKey)
        try:
         if currentKey.values:
          for value in currentKey.values:
             ValueNode(self, knode, self.node, value)
        except Exception as e:
           pass
        self.updateCount()
        return knode
    
    def optim(self, current, parent):
        if self.iter.first_subkey():
            cursub = self.iter.current_subkey()
            knode = self.createNode(parent, current)
            while cursub:
                self.iter.down()
                self.optim(cursub, knode)
                cursub = self.iter.next_subkey()
            self.iter.up()
        else:
            knode = self.createNode(parent, current)
            self.iter.up()

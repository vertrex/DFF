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

from dff.api.module.module import *
from dff.api.vfs.vfs import vfs

HKLM_PATH = ["/WINDOWS/system32/config/software",
             "/WINDOWS/system32/config/system",
             "/WINDOWS/system32/config/default",
             "/WINDOWS/system32/config/SAM",
             "/WINDOWS/system32/config/SECURITY"]

HKUSERS = "/Documents and Settings/"


class rootManager():
    def __init__(self, mountpoint):
        self.vfs = vfs()
        self.mountpoint = mountpoint
        self.hives = []

    def checkGeneration(self):
        if self.mountpoint.fsobj().name in ("ntfs", "fat"):
            return True
        return False

    def getHives(self):
        if self.checkGeneration():
            hives = []
            rootpath = self.mountpoint.absolute()
            for path in HKLM_PATH:
                print rootpath + path
                n = self.vfs.getnode(rootpath + path)
                hives.append(n)
            return hives
                
class pathManager():
    def __init__(self, hive, path=None):
        self.setPath(path)
        self.hive = hive
        self.iterator = self.hive.__iter__()

    def setPath(self, path):
        if path == "":
            self.path = None
        else:
            self.path = path

    def splitPath(self, path):
        if path:
            rpath = path[1:len(path)]
            return rpath.split('/')
        else:
            return None

    def getValues(self):
        key = self.getKey()
        if key and len(key.values) > 0:
            return key.values
        else:
            return None

    def getKey(self):
        if not self.path:
            return None
        else:
            self.iterator.descend(self.splitPath(self.path))
            ckey = self.iterator.current_key()
            if ckey:
                return ckey
            else:
                return None

    def getSecurity(self):
        key = self.getKey()
        if key:
            return self.key.fetch_security()
        return None

    def getClassName(self):
        key = self.getKey()
        if key:
            return self.key.fetch_classname()
        return None

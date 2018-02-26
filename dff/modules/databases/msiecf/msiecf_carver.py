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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 

from decoder import *
from msiecf_header import *
from hash_records import *
from hash_table import *

BLOCK_SIZE = 0x80

LEAK_HEAD = "LEAK"
HASH_HEAD = "HASH"
URL_HEAD = "URL "
REDR_HEAD = "REDR"

HEAD_SIZE = 0x4

BLOCK_SIZE = 0x80

class MSIECFCarver:
    def __init__(self, node):
        self.node = vfile

        self.header = Header(self.node)
        if self.header.isValid():
            self.configure()

    def configure(self):
        self.__leaks = []
        self.__urls = []
        self.__redrs = []
        self.__hashs = []

        self.__bsize = BLOCK_SIZE
        # Default Configuration
        self.__optLEAK = True
        self.__optURL = True
        self.__optREDR = True
        self.__optHASH = False

    def carveLEAK(self, state):
        self.__optLEAK = state

    def carveURL(self, state):
        self.__optURL = state

    def carveHASH(self, state):
        self.__optHASH = state

    def carveREDR(self, state):
        self.__optREDR = state

    def process(self):
	vfile = self.node.open()
        vfile.seek(0)
        curoffset = 0
        while curoffset < self.header.filesize:
            vfile.seek(curoffset)
            tag = vfile.read(HEAD_SIZE)

            if self.__optURL and tag == URL_HEAD:
                self.__urls.append(Url(node, curoffset))
            elif self.__optLEAK and tag == LEAK_HEAD:
                self.__leaks.append(Leak(node, curoffset))
            elif self.__optREDR and tag == REDR_HEAD:
                self.__redrs.append(Redr(node, curoffset))
            elif self.__optHASH and tag == HASH_HEAD:
                self.__hashs.append(HashTable(node, curoffset))

            curoffset += self.__bsize
	vfile.close()

    def urls(self):
        return self.__urls

    def leaks(self):
        return self.__leaks

    def redrs(self):
        return self.__redrs

    def hashs(self):
        return self.__hashs

#        inn = False
#        u = Url(vfile, curoffset)
#        print "URL LOC : ", u.location()
#        for entry in roothashtab.entries:
#            if entry.url:
#                if entry.url.offset == u.offset:
#                    inn = True
#       if not inn:
#            print "NOT IN at : ", hex(curoffset)
#            print "DUMMMMMMPPP"
#            u.dump()
#            print u.Filename
#f            entry.Url.dump()
#    elif h == "RED":
#        rdr = Redr(vfile, curoffset)
#        print "REDR LOC : ", rdr.location()
#    elif h == "LEA":
#        lea = Leak(vfile, curoffset)
#        print "LEAK FN : ", lea.filename()
#    curoffset += 0x80


        

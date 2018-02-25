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

BITMAP_OFFSET = 0x250

class bitmap:
    def __init__(self, vfile, offset=BITMAP_OFFSET):
        self.vfile = vfile
        self.offset = offset

    def byte_to_bits_string(self, x):
        return "".join(map(lambda y:str((x>>y)&1), range(7, -1, -1))) 

    def bytes_to_bits(self, bytes):
        bits_list = []
        for i in bytes:
            bits_list += self.byte_to_bits_string(i)[::-1]
        return bits_list

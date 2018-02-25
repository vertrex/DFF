#!/usr/bin/python
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
#  Solal J. <sja@digital-forensic.org>
#

import os, sys

if __name__ == "__main__":
   if len(sys.argv) == 2:
     file = open(sys.argv[1], 'r') 
     fbuff = file.read()
     if fbuff.find("import exceptions") == -1:
       buff = "import exceptions\n"
       buff += fbuff
     else:
       buff = fbuff
     file.close()
     buff = buff.replace('Error(_object)', 'Error(exceptions.Exception)')
     buff = buff.replace('Error(object)', 'Error(exceptions.Exception)')
     file = open(sys.argv[1], 'w')
     file.write(buff)
     file.close()
